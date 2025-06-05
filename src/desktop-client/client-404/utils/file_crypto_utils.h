#ifndef FILE_CRYPTO_UTILS_H
#define FILE_CRYPTO_UTILS_H

#include <QString>
#include <QByteArray>
#include <QJsonObject>
#include <QMessageBox>
#include <QWidget>
#include "utils/securevector.h"

class FileCryptoUtils {
public:
    // Key storage operations
    static bool saveKeyToLocalStorage(const QString &fileUuid, 
                                     const unsigned char *key, 
                                     size_t keyLen,
                                     QWidget* parentWidget = nullptr);

    static bool readAndDecryptKeyStorage(const QString &filepath, 
                                        const SecureVector &masterKey,
                                        QByteArray &jsonData,
                                        QWidget* parentWidget = nullptr);

    static bool encryptAndSaveKeyStorage(const QString &filepath,
                                       const QByteArray &jsonData,
                                       const SecureVector &masterKey,
                                       QWidget* parentWidget = nullptr);

    // File metadata operations
    static QByteArray formatFileMetadata(const QString &fileName, 
                                        const QString &fileType, 
                                        qint64 fileSize);

    // File decryption helpers
    static bool getFileEncryptionKey(const QString &fileUuid, 
                                    unsigned char *key, 
                                    size_t keyLen,
                                    QWidget* parentWidget = nullptr);

    // Build the key storage file path for the currently logged-in user
    static QString buildKeyStorageFilePath();
    
    // Make these methods public so they can be used by FileSharingUtils
    static bool validateKeyParameters(const unsigned char *key, 
                                    size_t keyLen, 
                                    QWidget* parentWidget = nullptr);
                                    
    static bool validateMasterKey(const SecureVector &masterKey, 
                                QWidget* parentWidget = nullptr);

private:
    // Helper methods for key storage
    static bool addKeyToJsonStorage(const QByteArray &jsonData,
                                   const QString &fileUuid,
                                   const unsigned char *key,
                                   size_t keyLen,
                                   QByteArray &updatedJsonData,
                                   QWidget* parentWidget = nullptr);
};

#endif // FILE_CRYPTO_UTILS_H
