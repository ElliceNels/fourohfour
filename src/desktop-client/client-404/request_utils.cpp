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
    m_refreshToken = token.empty() ? nullopt : make_optional<string>(token);
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
        m_headers = curl_slist_append(m_headers, refreshHeader.c_str());
        // Zero out the memory for security
        clearRefreshToken();
    }
}

// Attempt to refresh access token using refresh token
bool RequestUtils::refreshAccessToken() {
    if (!m_refreshToken || m_tokenRefreshInProgress) {
        return false;
    }
    
    // Set flag to prevent recursive token refresh
    m_tokenRefreshInProgress = true;
    
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
    m_tokenRefreshInProgress = false;
    return success;
}

// Destructor
RequestUtils::~RequestUtils() {
    if (m_headers) {
        curl_slist_free_all(m_headers);
    }
    if (m_curl) {
        curl_easy_cleanup(m_curl);
    }
    clearBearerToken();
    clearRefreshToken();
}

// Set up CURL with secure defaults
void RequestUtils::setupCurl() {
    curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, ENABLED);
    curl_easy_setopt(m_curl, CURLOPT_MAXREDIRS, MAX_REDIRECTS);
    curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, TIMEOUT_SECONDS);
    curl_easy_setopt(m_curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
    curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, ENABLED);
    curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, SSL_VERIFY_HOST_STRICT);
    curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, RequestUtils::writeCallback);
    curl_easy_setopt(m_curl, CURLOPT_DOH_URL, DNS_URL_DOH.c_str());
    curl_easy_setopt(m_curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
}

// Reset headers
void RequestUtils::resetHeaders() {
    if (m_headers) {
        curl_slist_free_all(m_headers);
        m_headers = nullptr;
    }
    m_headers = curl_slist_append(m_headers, CONTENT_TYPE_JSON.c_str());
    m_headers = curl_slist_append(m_headers, ACCEPT_JSON.c_str());
    if (m_bearerToken) {
        string auth = AUTH_BEARER_PREFIX + *m_bearerToken;
        m_headers = curl_slist_append(m_headers, auth.c_str());
        sodium_memzero(auth.data(), auth.size());
    }
}

// Set bearer token
void RequestUtils::setBearerToken(const string& token) {
    if (token.empty()) {
        throw invalid_argument("Bearer token cannot be empty");
    }
    m_bearerToken = make_optional<string>(token);
    resetHeaders();
}

// Clear bearer token
void RequestUtils::clearBearerToken() {
    if (m_bearerToken) {
        sodium_memzero(m_bearerToken->data(), m_bearerToken->size());
        m_bearerToken.reset();
    }
    resetHeaders();
}

// Write callback for response data
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

// Core request method
RequestUtils::Response RequestUtils::makeRequest(const string& url, HttpMethod method,
                                                const QJsonObject& data, const QJsonObject& params) {
    Response response{0, QJsonDocument(), "", false, ""};
    string responseData;

    // Reset CURL handle
    curl_easy_reset(m_curl);
    setupCurl();

    // Construct full URL using QUrl
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

    string finalUrl = fullUrl.toString().toStdString();
    finalUrl = validateHttpsUrl(finalUrl);

    // Set CURL options
    curl_easy_setopt(m_curl, CURLOPT_URL, finalUrl.c_str());
    curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &responseData);
    curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, m_headers);

    // Configure method and body
    string jsonData;
    if (method == HttpMethod::GET) {
        curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1L);
    } else {
        if (method == HttpMethod::POST) {
            curl_easy_setopt(m_curl, CURLOPT_POST, 1L);
        } else {
            curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, httpMethodToString(method).c_str());
        }

        if (!data.isEmpty()) {
            jsonData = jsonToString(data);
            curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, jsonData.c_str());
            curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, jsonData.length());
        }
    }

    // Perform request with retry logic
    const int maxRetries = 3;
    int retryCount = 0;
    CURLcode res;
    do {
        res = curl_easy_perform(m_curl);
        if (res == CURLE_OK) {
            break;
        }
        retryCount++;
        if (retryCount >= maxRetries) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    } while (res == CURLE_OPERATION_TIMEDOUT || res == CURLE_COULDNT_CONNECT);

    if (res != CURLE_OK) {
        std::cout << "CURL error: " << curl_easy_strerror(res) << std::endl;  // Use cout instead of cerr
        response.success = false;
        response.errorMessage = curl_easy_strerror(res);
        return response;
    }

    // Get status code
    curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &response.statusCode);
    response.success = (response.statusCode >= 200 && response.statusCode < 300);
    response.rawData = std::move(responseData);

    // Get content type
    char* contentType = nullptr;
    curl_easy_getinfo(m_curl, CURLINFO_CONTENT_TYPE, &contentType);

    // Parse JSON if content type is application/json
    if (contentType && strstr(contentType, "application/json") && !response.rawData.empty()) {
        QJsonParseError parseError;
        QJsonDocument jsonDoc = QJsonDocument::fromJson(QByteArray::fromStdString(response.rawData), &parseError);
        if (parseError.error == QJsonParseError::NoError) {
            response.jsonData = jsonDoc;
        } else {
            std::cout << "JSON parse error: " << parseError.errorString().toStdString() << std::endl;  // Use cout
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
                response.errorMessage = "HTTP error: " + std::to_string(response.statusCode);
            }
        } else {
            response.errorMessage = "HTTP error: " + std::to_string(response.statusCode);
        }
        std::cout << "HTTP error: " << response.statusCode << " - " << response.errorMessage << std::endl;  // Use cout
    }

    // Handle token expiration (status code 401)
    if (response.statusCode == 401 && m_refreshToken && !m_tokenRefreshInProgress && 
        url != REFRESH_TOKEN_ENDPOINT) {
        if (refreshAccessToken()) {
            return makeRequest(url, method, data, params);
        }
    }

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