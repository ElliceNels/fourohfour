#ifndef FILE_SHARING_UTILS_H
#define FILE_SHARING_UTILS_H

#include <QVector>
#include <QByteArray>
#include <QJsonArray>
#include "utils/securevector.h"

class FileSharingUtils {

    public:
        static QJsonArray generateOneTimePreKeyPairs();
        
        static bool generateSignedPreKey(
            const QString& identityPublicKeyBase64,
            const QString& identityPrivateKeyBase64,
            QString& signedPreKeyPublic,
            QString& signedPreKeyPrivate,
            QString& signature);
            
        static bool verifySignedPreKey(
            const QString& identityPublicKeyBase64,
            const QString& signedPreKeyPublicBase64,
            const QString& signatureBase64);
            
        static bool generateEphemeralKeyPair(
            QString& ephemeralPublicKey,
            QString& ephemeralPrivateKey);
            
    private:
        // Helper method to save signed pre-key pair
        static bool saveSignedPreKeyLocally(const QString& publicKeyBase64, 
                                    const QString& privateKeyBase64);
                                    
        // Generic key storage method that can be used for different key types
        static bool saveKeyPairsLocally(const QString& keyType,
                                const QVector<QByteArray>& publicKeys,
                                const QVector<QByteArray>& privateKeys);
                              
        // Original method - will be refactored to use the generic method
        static bool saveOneTimePreKeyPairsLocally(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys);
        
        // Helper methods for key storage
        static bool validateKeyPairs(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys);
        static SecureVector getMasterKey();
        static QString buildKeyStorageFilePath();
        static bool readAndDecryptKeyStorage(const QString &filepath, 
                                     const SecureVector &masterKey, 
                                     QByteArray &jsonData);
        static bool updateJsonWithKeysGeneric(const QByteArray &jsonData,
                                     const QString& keyType, 
                                     const QVector<QByteArray>& publicKeys, 
                                     const QVector<QByteArray>& privateKeys,
                                     QByteArray &updatedJsonData);
        static bool encryptAndSaveKeyStorage(const QString &filepath, 
                                     const QByteArray &jsonData, 
                                     const SecureVector &masterKey);
};

#endif // FILE_SHARING_UTILS_H
