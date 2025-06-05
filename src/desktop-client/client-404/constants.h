#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>
#include <QRegularExpression>

using namespace std;

// File upload constants
namespace FileUpload {
    // encryption overhead:
    // - XChaCha20-Poly1305 nonce (24 bytes)
    // - Authentication tag (16 bytes)
    constexpr qint64 ENCRYPTION_OVERHEAD_BYTES = 40;
    
    // Exact database constraint (100MB)
    constexpr qint64 SERVER_MAX_SIZE_BYTES = 104857600;
    
    // File size constants
    constexpr qint64 KB = 1024;
    constexpr qint64 MB = 1024 * 1024;
    constexpr qint64 GB = 1024 * 1024 * 1024;
}

const qint64 KEY_GEN_COUNT = 50; // Number of one-time pre-keys to generate
const QString keysPath = "/encryptedKeys_";
const QString masterKeyPath = "/masterKey_";
const QString friendsDirectory = "friends";
const QString certsDirectory = "certs";
const QString certName = "cacert.pem";
const QString certsPath = "";
const QString friendsPath = "friends_";

const QString jsonExtension = ".json";
const QString binaryExtension = ".bin";
const int MAX_LOGIN_ATTEMPTS = 5;
const int RATE_LIMIT_WINDOW_MS = 300000; // 5 minutes in milliseconds
const double truncationFactor = 0.75;
const int fileNameLabelWidth = 320;
const int fileSizeLabelWidth = 80;
const QString serverPath = "https://fourohfour.gobbler.info";
//"https://fourohfour.gobbler.info/";
//http://gobbler.info:4004
//http://localhost:5000

const int fileOwnerLabelWidth = 200;
const int usernameLabelWidth = 400;
const float friendTruncationFactor = 0.9;

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
const std::string DEFAULT_BASE_URL = "https://fourohfour.gobbler.info"; 

// API paths
const std::string REFRESH_TOKEN_ENDPOINT = "/refresh";
const std::string SIGN_UP_ENDPOINT = "/sign_up";
const std::string LOGIN_ENDPOINT = "/login";
const std::string FILES_API_ENDPOINT = "/api/files";
const std::string UPLOAD_FILE_ENDPOINT = FILES_API_ENDPOINT + "/upload";
const std::string GET_PUBLIC_KEY_ENDPOINT = "/get_public_key";
const std::string RETRIEVE_KEY_BUNDLE_ENDPOINT = "/retrieve_key_bundle";
const std::string RESET_PASSWORD_ENDPOINT = "/change_password";
const std::string GET_USER_ENDPOINT = "/get_current_user";
const std::string GET_USER_FILES_ENDPOINT =  FILES_API_ENDPOINT + "/";
const std::string ADD_OTPKS_ENDPOINT = "/add_otpks";
const std:: string CREATE_PERMISSION_ENDPOINT = "/api/permissions";

const int MAX_AGE_DAYS = 7; // Maximum age of signed prekey in days

//source: https://stackoverflow.com/questions/2053335/what-should-be-the-valid-characters-in-usernames
const QString RESTRICTED_CHARS = QStringLiteral("\\/:*?\"<>|'%;&=+$#@!~()[]{}., ");
inline const QRegularExpression RESTRICTED_CHARS_REGEX("[" + QRegularExpression::escape(RESTRICTED_CHARS) + "]");

const int OWNED_FILES_PAGE_INDEX = 0;
const int SHARED_FILES_PAGE_INDEX = 1;

// View Files Page Indices
const int FILES_LIST_PAGE_INDEX = 0;
const int SHARING_PAGE_INDEX = 1;
const int FRIENDS_LIST_PAGE_INDEX = 2;

const int FIND_FRIEND_INDEX = 0;
const int VERIFY_PUBLIC_KEY_INDEX = 1;

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

const QString SuccessMessage = R"(
    color: #4CAF50; 
    font-weight: bold;
    font-size: 14px;
)";

const QString ErrorMessage = R"(
    color: #F44336; 
    font-weight: bold;
    font-size: 14px;
)";
}

#endif // CONSTANTS_H
