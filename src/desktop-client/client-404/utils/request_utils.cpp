#include "request_utils.h"
#include <QUrlQuery>
#include <QUrl>
#include <string>
#include <mutex>
#include <thread>
#include <chrono>
#include <iostream> 
#include "constants.h"

using namespace std;

// Static initialization flag
bool RequestUtils::s_globalInitialized = false;
// Static mutex for thread safety
mutex RequestUtils::s_initMutex;

// Static method for global curl initialization
bool RequestUtils::globalInit() {
    lock_guard<mutex> lock(s_initMutex);
    if (!s_globalInitialized) {
        CURLcode result = curl_global_init(CURL_GLOBAL_DEFAULT);
        s_globalInitialized = (result == CURLE_OK);
        return s_globalInitialized;
    }
    return true;
}

// Static method for global curl cleanup
void RequestUtils::globalCleanup() {
    lock_guard<mutex> lock(s_initMutex);
    if (s_globalInitialized) {
        curl_global_cleanup();
        s_globalInitialized = false;
    }
}

// Constructor
RequestUtils::RequestUtils() : m_curl(curl_easy_init()) {
    if (!m_curl) {
        throw runtime_error("Failed to initialize libcurl");
    }
    setupCurl();
    resetHeaders();
    clearBearerToken();
    clearRefreshToken();
}

// Set refresh token
void RequestUtils::setRefreshToken(const string& token) {
    if (token.empty()) {
        throw invalid_argument("Refresh token cannot be empty");
    }
    m_refreshToken = token;
}

// Clear refresh token
void RequestUtils::clearRefreshToken() {
    if (m_refreshToken) {
        sodium_memzero(m_refreshToken->data(), m_refreshToken->size());
        m_refreshToken.reset();
    }
}

// Add refresh token header for specific requests (like logout)
void RequestUtils::addRefreshTokenHeader() {
    if (m_refreshToken) {
        string refreshHeader = REFRESH_TOKEN_HEADER + *m_refreshToken;
        m_headers.reset(curl_slist_append(m_headers.release(), refreshHeader.c_str()));
        // Zero out the memory for security
        clearRefreshToken();
    }
}

// Attempt to refresh access token using refresh token
bool RequestUtils::refreshAccessToken() {
    if (!m_refreshToken || m_tokenRefreshInProgress.load()) {
        return false;
    }
    
    // Set flag to prevent recursive token refresh
    m_tokenRefreshInProgress.store(true);
    
    // Create a request body with refresh token
    QJsonObject data;
    data["refresh_token"] = QString::fromStdString(*m_refreshToken);
    
    // Store current access token temporarily
    auto oldAccessToken = m_bearerToken;
    
    // Clear access token for this request
    clearBearerToken();
    
    // Make request to refresh token endpoint
    Response response = post(REFRESH_TOKEN_ENDPOINT, data);
    
    // Check if refresh was successful
    bool success = false;
    if (response.success && !response.jsonData.isEmpty()) {
        QJsonObject jsonObj = response.jsonData.object();
        if (jsonObj.contains("access_token")) {
            // Update the access token
            setBearerToken(jsonObj["access_token"].toString().toStdString());
            success = true;
        }
    }
    
    // If refresh failed, restore the old token
    if (!success && oldAccessToken) {
        setBearerToken(*oldAccessToken);
    }
    
    // Reset flag
    m_tokenRefreshInProgress.store(false);  
    return success;
}

// Destructor - no longer needs manual cleanup
RequestUtils::~RequestUtils() {
    clearBearerToken();
    clearRefreshToken();
    // Smart pointers will handle cleanup of m_curl and m_headers
}

// Set up CURL with secure defaults
void RequestUtils::setupCurl() {
    curl_easy_setopt(m_curl.get(), CURLOPT_FOLLOWLOCATION, ENABLED);    // Allow redirects to be followed automatically
    curl_easy_setopt(m_curl.get(), CURLOPT_MAXREDIRS, MAX_REDIRECTS);   // Limit redirects to 5 to prevent redirect loops
    curl_easy_setopt(m_curl.get(), CURLOPT_TIMEOUT, TIMEOUT_SECONDS);   // Set 30 second timeout for entire request
    curl_easy_setopt(m_curl.get(), CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);  // Use TLS 1.3 for stronger encryption
    curl_easy_setopt(m_curl.get(), CURLOPT_SSL_VERIFYPEER, ENABLED);    // Verify the authenticity of the SSL certificate
    curl_easy_setopt(m_curl.get(), CURLOPT_SSL_VERIFYHOST, SSL_VERIFY_HOST_STRICT); // Verify the SSL cert matches the hostname
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, RequestUtils::writeCallback); // Set callback for handling response data
    curl_easy_setopt(m_curl.get(), CURLOPT_DOH_URL, DNS_URL_DOH.c_str()); // Use DNS over HTTPS for secure hostname resolution
    curl_easy_setopt(m_curl.get(), CURLOPT_REDIR_PROTOCOLS_STR, "http,https"); // Only allow redirects to HTTP/HTTPS protocols
}

// Reset headers
void RequestUtils::resetHeaders() {
    // Release old list and create a new one
    m_headers.reset(nullptr);
    m_headers.reset(curl_slist_append(nullptr, CONTENT_TYPE_JSON.c_str()));
    m_headers.reset(curl_slist_append(m_headers.release(), ACCEPT_JSON.c_str()));
    
    if (m_bearerToken) {
        string auth = AUTH_BEARER_PREFIX + *m_bearerToken;
        m_headers.reset(curl_slist_append(m_headers.release(), auth.c_str()));
        sodium_memzero(auth.data(), auth.size());
    }
}

/**
 * @brief Sets the bearer token for authentication
 * 
 * @param token The bearer token string to use for authorization
 * @throws invalid_argument if token is empty
 */
void RequestUtils::setBearerToken(const string& token) {
    if (token.empty()) {
        throw invalid_argument("Bearer token cannot be empty");
    }
    m_bearerToken = make_optional<string>(token);
    resetHeaders();
}

/**
 * @brief Clears the current bearer token and securely wipes it from memory
 */
void RequestUtils::clearBearerToken() {
    if (m_bearerToken) {
        sodium_memzero(m_bearerToken->data(), m_bearerToken->size());
        m_bearerToken.reset();
    }
    resetHeaders();
}

/**
 * @brief Callback function for libcurl to write received data
 * 
 * @param contents Pointer to the received data
 * @param size Size of each data element
 * @param nmemb Number of data elements
 * @param userp User pointer (where to store the data)
 * @return Size of processed data
 */
size_t RequestUtils::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realSize = size * nmemb;
    auto* response = static_cast<string*>(userp);
    response->append(static_cast<char*>(contents), realSize);
    return realSize;
}

// Convert QJsonObject to string
string RequestUtils::jsonToString(const QJsonObject& json) {
    QJsonDocument doc(json);
    return doc.toJson(QJsonDocument::Compact).toStdString();
}

// Validate HTTPS URL
string RequestUtils::validateHttpsUrl(const string& url) {
    QUrl qurl(QString::fromStdString(url));
    if (qurl.scheme() != "https") {
        throw runtime_error("Only HTTPS URLs are allowed: " + url);
    }
    return url;
}

// Convert HttpMethod to string
string RequestUtils::httpMethodToString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET:    return "GET";
        case HttpMethod::POST:   return "POST";
        case HttpMethod::DELETE_: return "DELETE";  // Ensure we're using DELETE_ consistently
        default:                 return "GET";
    }
}

/**
 * @brief Builds a complete URL from base URL, relative URL and query parameters
 * 
 * @param url The relative URL path
 * @param params Query parameters as a QJsonObject
 * @return Complete HTTPS URL as string
 * @throws runtime_error if the URL is not HTTPS
 */
string RequestUtils::buildRequestUrl(const string& url, const QJsonObject& params) {
    QUrl baseUrl(QString::fromStdString(m_baseUrl));
    QUrl relativeUrl(QString::fromStdString(url));
    QUrl fullUrl = baseUrl.resolved(relativeUrl);

    if (!params.isEmpty()) {
        QUrlQuery query;
        for (auto it = params.begin(); it != params.end(); ++it) {
            query.addQueryItem(it.key(), it.value().toVariant().toString());
        }
        fullUrl.setQuery(query);
    }
    
    return validateHttpsUrl(fullUrl.toString().toStdString());
}

/**
 * @brief Configures the HTTP method and request body for the current request
 * 
 * @param method HTTP method to use (GET, POST, DELETE_, etc.)
 * @param data Request body data as QJsonObject (for non-GET requests)
 */
void RequestUtils::configureRequestMethod(HttpMethod method, const QJsonObject& data) {
    string jsonData;
    
    if (method == HttpMethod::GET) {
        curl_easy_setopt(m_curl.get(), CURLOPT_HTTPGET, 1L);
    } else {
        if (method == HttpMethod::POST) {
            curl_easy_setopt(m_curl.get(), CURLOPT_POST, 1L);
        } else {
            curl_easy_setopt(m_curl.get(), CURLOPT_CUSTOMREQUEST, httpMethodToString(method).c_str());
        }

        if (!data.isEmpty()) {
            jsonData = jsonToString(data);
            curl_easy_setopt(m_curl.get(), CURLOPT_POSTFIELDS, jsonData.c_str());
            curl_easy_setopt(m_curl.get(), CURLOPT_POSTFIELDSIZE, jsonData.length());
        }
    }
}

/**
 * @brief Performs the HTTP request with automatic retry for timeout and connection errors
 * 
 * @param responseData Reference to string where response data will be stored
 * @return CURLcode result of the operation
 */
CURLcode RequestUtils::performRequestWithRetry(string& responseData) {
    const int maxRetries = 3;
    int retryCount = 0;
    CURLcode res;
    
    do {
        res = curl_easy_perform(m_curl.get());
        if (res == CURLE_OK) {
            break;
        }
        retryCount++;
        if (retryCount >= maxRetries) {
            break;
        }
        this_thread::sleep_for(chrono::seconds(1));
    } while (res == CURLE_OPERATION_TIMEDOUT || res == CURLE_COULDNT_CONNECT);
    
    return res;
}

/**
 * @brief Processes HTTP response data, extracts status code, parses JSON, and handles errors
 * 
 * @param response Reference to Response object to populate
 * @param responseData Raw response data as string
 */
void RequestUtils::processResponse(Response& response, const string& responseData) {
    // Get status code
    curl_easy_getinfo(m_curl.get(), CURLINFO_RESPONSE_CODE, &response.statusCode);
    response.success = (response.statusCode >= 200 && response.statusCode < 300);
    response.rawData = responseData;

    // Get content type
    char* contentType = nullptr;
    curl_easy_getinfo(m_curl.get(), CURLINFO_CONTENT_TYPE, &contentType);

    // Parse JSON if content type is application/json
    if (contentType && strstr(contentType, "application/json") && !response.rawData.empty()) {
        QJsonParseError parseError;
        QJsonDocument jsonDoc = QJsonDocument::fromJson(QByteArray::fromStdString(response.rawData), &parseError);
        if (parseError.error == QJsonParseError::NoError) {
            response.jsonData = jsonDoc;
        } else {
            cout << "JSON parse error: " << parseError.errorString().toStdString() << endl;
            response.errorMessage = "JSON parse error: " + parseError.errorString().toStdString();
        }
    }

    // Extract error details for HTTP errors
    if (!response.success) {
        if (!response.jsonData.isEmpty()) {
            QJsonObject jsonObj = response.jsonData.object();
            if (jsonObj.contains("error")) {
                response.errorMessage = jsonObj["error"].toString().toStdString();
            } else if (jsonObj.contains("message")) {
                response.errorMessage = jsonObj["message"].toString().toStdString();
            } else {
                response.errorMessage = "HTTP error: " + to_string(response.statusCode);
            }
        } else {
            response.errorMessage = "HTTP error: " + to_string(response.statusCode);
        }
        cout << "HTTP error: " << response.statusCode << " - " << response.errorMessage << endl;
    }
}

/**
 * @brief Handles authentication errors by attempting token refresh when needed
 * 
 * @param response Reference to the current Response object
 * @param url Original request URL
 * @param method Original HTTP method
 * @param data Original request data
 * @param params Original request parameters
 * @return true if authentication was refreshed and request retried, false otherwise
 */
bool RequestUtils::handleAuthenticationError(Response& response, const string& url, HttpMethod method, 
                                           const QJsonObject& data, const QJsonObject& params) {
    // Handle token expiration (status code 401)
    if (response.statusCode == 401 && m_refreshToken && !m_tokenRefreshInProgress.load() && 
        url != REFRESH_TOKEN_ENDPOINT) {
        if (refreshAccessToken()) {
            response = makeRequest(url, method, data, params);
            return true;
        }
    }
    return false;
}

/**
 * @brief Core request method that handles all HTTP requests
 * 
 * This method orchestrates the entire HTTP request process:
 * 1. Prepares the request (URL, headers, method)
 * 2. Executes the request with retry logic
 * 3. Processes the response
 * 4. Handles authentication errors
 * 
 * @param url The API endpoint URL (relative to base URL)
 * @param method HTTP method to use
 * @param data Request body for POST/PUT/DELETE requests
 * @param params Query parameters for GET requests
 * @return Response object containing status, data and error information
 */
RequestUtils::Response RequestUtils::makeRequest(const string& url, HttpMethod method,
                                                const QJsonObject& data, const QJsonObject& params) {
    Response response{0, QJsonDocument(), "", false, ""};
    string responseData;

    // Reset CURL handle
    curl_easy_reset(m_curl.get());
    setupCurl();

    // Build full URL with query parameters
    string finalUrl = buildRequestUrl(url, params);
    curl_easy_setopt(m_curl.get(), CURLOPT_URL, finalUrl.c_str());
    curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, &responseData);
    curl_easy_setopt(m_curl.get(), CURLOPT_HTTPHEADER, m_headers.get());

    // Configure HTTP method and request body
    configureRequestMethod(method, data);

    // Execute the request with retry logic
    CURLcode res = performRequestWithRetry(responseData);
    if (res != CURLE_OK) {
        cout << "CURL error: " << curl_easy_strerror(res) << endl;
        response.success = false;
        response.errorMessage = curl_easy_strerror(res);
        return response;
    }

    // Process response
    processResponse(response, responseData);

    // Handle authentication errors
    handleAuthenticationError(response, url, method, data, params);

    return response;
}

// HTTP methods
RequestUtils::Response RequestUtils::get(const string& url, const QJsonObject& params) {
    return makeRequest(url, HttpMethod::GET, {}, params);
}

RequestUtils::Response RequestUtils::post(const string& url, const QJsonObject& data) {
    return makeRequest(url, HttpMethod::POST, data, {});
}

// DELETE request
RequestUtils::Response RequestUtils::del(const string& url, const QJsonObject& data) {
    return makeRequest(url, HttpMethod::DELETE_, data, {});  // Use DELETE_ consistently
}