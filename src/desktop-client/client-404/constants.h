#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>

constexpr qint64 MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;  // 100 MB in bytes
const QString keysPath = "/encryptedKeys_";
const QString masterKeyPath = "/masterKey_";
const QString binaryExtension = ".bin";
const double truncationFactor = 0.75;
const int fileNameLabelWidth = 320;
const int fileSizeLabelWidth = 60;
const int fileOwnerLabelWidth = 200;

const QString previewIconPath = ":/images/eye-bold.svg";
const QString shareIconPath = ":/images/share-fat-fill.svg";
const QString deleteIconPath = ":/images/trash-fill.svg";
const QString downloadIconPath =":/images/download-simple-bold.svg";

//source: https://stackoverflow.com/questions/2053335/what-should-be-the-valid-characters-in-usernames
constexpr std::string_view RESTRICTED_CHARS = R"(\/:*?"<>|'%;&=+$#@!~()[]{}., )";

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
