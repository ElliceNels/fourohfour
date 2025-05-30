#ifndef REQUEST_UTILS_H
#define REQUEST_UTILS_H

// Prevent Windows.h from defining 'bytes'
#ifdef _WIN32
    #define bytes win_bytes_override
    #include <Windows.h>
    #undef bytes
#endif

#include <curl/curl.h>
#include <QString>
#include <QJsonObject>
#include <QJsonDocument>
#include <string>
#include <optional>
#include <sodium.h>
#include <mutex>

using namespace std;

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE_  
};

class RequestUtils {
public:
    struct Response {
        long statusCode;
        QJsonDocument jsonData;
        std::string rawData;
        bool success;
        std::string errorMessage;
    };

    // Static methods for global initialization and cleanup
    static bool globalInit();
    static void globalCleanup();

    // Constructor and destructor
    RequestUtils();
    ~RequestUtils();

    // Token management methods
    void setBearerToken(const std::string& token);
    void clearBearerToken();
    void setRefreshToken(const std::string& token);
    void clearRefreshToken();
    void addRefreshTokenHeader();
    bool refreshAccessToken();

    // Base URL setter
    void setBaseUrl(const std::string& baseUrl);

    // HTTP request methods
    Response get(const std::string& url, const QJsonObject& params = QJsonObject());
    Response post(const std::string& url, const QJsonObject& data = QJsonObject());
    Response del(const std::string& url, const QJsonObject& data = QJsonObject());

private:
    // Static members
    static bool s_globalInitialized;
    static std::mutex s_initMutex;

    // Instance members
    CURL* m_curl = nullptr;
    struct curl_slist* m_headers = nullptr;
    string m_baseUrl;
    optional<string> m_bearerToken;
    optional<string> m_refreshToken;
    bool m_tokenRefreshInProgress = false;

    // Private utility methods
    void setupCurl();
    void resetHeaders();
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);
    std::string jsonToString(const QJsonObject& json);
    std::string validateHttpsUrl(const std::string& url);
    std::string httpMethodToString(HttpMethod method);
    Response makeRequest(const std::string& url, HttpMethod method,
                         const QJsonObject& data, const QJsonObject& params);
};

#endif 