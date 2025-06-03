#ifndef FILE_SHARING_UTILS_H
#define FILE_SHARING_UTILS_H

#include <QVector>
#include <QByteArray>
#include "utils/securevector.h"

class FileSharingUtils {

    public:
        QVector<QByteArray> generateOneTimePreKeyPairs();
    private:
        bool saveOneTimePreKeyPairsLocally(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys);
        
        // Helper methods for key storage
        bool validateKeyPairs(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys);
        SecureVector getMasterKey();
        QString buildKeyStorageFilePath();
        bool readAndDecryptKeyStorage(const QString &filepath, 
                                     const SecureVector &masterKey, 
                                     QByteArray &jsonData);
        bool updateJsonWithPrekeys(const QByteArray &jsonData, 
                                  const QVector<QByteArray>& publicKeys, 
                                  const QVector<QByteArray>& privateKeys,
                                  QByteArray &updatedJsonData);
        bool encryptAndSaveKeyStorage(const QString &filepath, 
                                     const QByteArray &jsonData, 
                                     const SecureVector &masterKey);
};

#endif // FILE_SHARING_UTILS_H
