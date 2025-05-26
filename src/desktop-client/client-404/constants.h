#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <QString>

constexpr qint64 MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;  // 100 MB in bytes
const QString CENTRAL_WIDGET_BACKGROUND = "background-color: rgb(231, 236, 239);";
const QString keysPath = "/encryptedKeys_";
const QString masterKeyPath = "/masterKey_";
const QString binaryExtension = ".bin";

#endif // CONSTANTS_H
