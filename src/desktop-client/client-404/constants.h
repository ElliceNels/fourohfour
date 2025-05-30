#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>

constexpr qint64 MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;  // 100 MB in bytes
const QString keysPath = "/encryptedKeys_";
const QString masterKeyPath = "/masterKey_";
const QString binaryExtension = ".bin";
const int MAX_LOGIN_ATTEMPTS = 5;
const int RATE_LIMIT_WINDOW_MS = 300000; // 5 minutes in milliseconds
const double truncationFactor = 0.75;
const int fileNameLabelWidth = 200;
const int fileSizeLabelWidth = 60;
const int fileOwnerLabelWidth = 100;
const QString serverPath = "http://gobbler.info:4004";
//http://gobbler.info:4004
//http://localhost:5000
const QString loginEndpoint = serverPath + "/login";
const QString registerEndpoint = serverPath + "/sign_up";

//source: https://stackoverflow.com/questions/2053335/what-should-be-the-valid-characters-in-usernames
constexpr std::string_view RESTRICTED_CHARS = R"(\/:*?"<>|'%;&=+$#@!~()[]{}., )";

namespace Styles {
const QString CentralWidget = R"(
            background-color: rgb(255, 255, 255);
        )";

const QString FileItem = R"(
            QWidget {
                background-color: #E7ECEF;
                border-bottom: 1px solid #8B8C89;
                padding: 8px;
            }

            QLabel {
                color: #274C77;
                font-weight: bold;
            }

            QPushButton {
                background-color: #6096BA;
                color: white;
                padding: 5px 10px;
                border-radius: 4px;
            }

            QPushButton:hover {
                background-color: #A3CEF1;
            }
        )";
}

#endif // CONSTANTS_H
