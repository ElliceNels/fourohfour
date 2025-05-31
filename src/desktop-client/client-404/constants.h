#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>

using namespace std;

constexpr qint64 MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;  // 100 MB in bytes
const QString keysPath = "/encryptedKeys_";
const QString masterKeyPath = "/masterKey_";
const QString binaryExtension = ".bin";
const int MAX_LOGIN_ATTEMPTS = 5;
const int RATE_LIMIT_WINDOW_MS = 300000; // 5 minutes in milliseconds
const double truncationFactor = 0.75;
const int fileNameLabelWidth = 320;
const int fileSizeLabelWidth = 60;
const QString serverPath = "http://gobbler.info:4004";
//http://gobbler.info:4004
//http://localhost:5000
const QString loginEndpoint = serverPath + "/login";
const QString registerEndpoint = serverPath + "/sign_up";
const int fileOwnerLabelWidth = 200;

const QString previewIconPath = ":/images/eye-bold.svg";
const QString shareIconPath = ":/images/share-fat-fill.svg";
const QString deleteIconPath = ":/images/trash-fill.svg";
const QString downloadIconPath =":/images/download-simple-bold.svg";

// Constants for HTTP request settings
const long ENABLED = 1L;
const long MAX_REDIRECTS = 5L;
const long TIMEOUT_SECONDS = 30L;
const long SSL_VERIFY_HOST_STRICT = 2L;
const std::string DNS_URL_DOH = "https://1.1.1.1/dns-query";

// HTTP Headers
const std::string CONTENT_TYPE_JSON = "Content-Type: application/json";
const std::string ACCEPT_JSON = "Accept: application/json";
const std::string AUTH_BEARER_PREFIX = "Authorization: Bearer ";
const std::string REFRESH_TOKEN_HEADER = "X-Refresh-Token: ";

// Default base URL for the server
// PRODUCTION: Enforce HTTPS only
// const std::string DEFAULT_BASE_URL = "https://gobbler.info/"; 

// DEVELOPMENT: Allow both HTTP and HTTPS for local testing
const std::string DEFAULT_BASE_URL = "http://127.0.0.1:5000"; 

// API paths
const std::string REFRESH_TOKEN_ENDPOINT = "/refresh";
const std::string SIGN_UP_ENDPOINT = "/sign_up";

//source: https://stackoverflow.com/questions/2053335/what-should-be-the-valid-characters-in-usernames
constexpr string_view RESTRICTED_CHARS = R"(\/:*?"<>|'%;&=+$#@!~()[]{}., )";

const int OWNED_FILES_PAGE_INDEX = 0;
const int SHARED_FILES_PAGE_INDEX = 1;

namespace Styles {
const QString CentralWidget = R"(
            background-color: rgb(255, 255, 255);
        )";

const QString FileItem = R"(
    QWidget {
        background-color: white;
        border-bottom: 1px solid #BDBDBD;
        padding: 8px 4px;
        margin: 0;
    }

    QLabel {
        color: #424242;
        background-color: transparent;
        border: none;
    }

    QLabel#fileNameLabel {
        font-weight: bold;
    }
)";
const QString TransparentButton = R"(
        QPushButton { 
            border: none; 
            background: transparent; 
        }
        QPushButton:hover { 
            background-color: #F0F0F0; 
            border-radius: 4px; 
        }
    )";

const QString SelectedSidebarButton = R"(
    background-color: #E3F2FD; 
    font-weight: bold; 
    color: #2196F3;
)";

const QString UnselectedSidebarButton = R"(
    background-color: transparent; 
    color: #424242;
)";
}

#endif // CONSTANTS_H
