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
            
        static bool retrieveRecipientKeyMaterialForX3DH(
            const QString& publicSignedPreKeyBase64,
            const QString& publicOneTimePreKeyBase64,
            QString& privateSignedPreKey,
            QString& privateOneTimePreKey,
            QString& privateKey);
            
        static bool removeOneTimePreKey(const QString& publicKeyBase64);
        
        /**
         * @brief Gets decrypted key storage data
         * 
         * This is a public wrapper around private key storage methods
         * to safely expose the functionality to other classes.
         * 
         * @param jsonData Output parameter that will contain the decrypted JSON data
         * @return bool True if successful, false otherwise
         */
        static bool getDecryptedKeyStorage(QByteArray& jsonData);

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
                                     
        // Helper method to extract keys from JSON storage
        static bool extractKeyFromStorage(const QJsonObject& rootObject,
                                 const QString& keyType,
                                 const QString& keyIdentifier,
                                 QString& extractedKey);
};

#endif // FILE_SHARING_UTILS_H
