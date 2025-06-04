#ifndef KEY_UTILS_H
#define KEY_UTILS_H

#include <QString>
#include <QWidget>
#include "crypto/encryptionhelper.h"
using namespace std;

bool saveFile(const QString &filePath, const SecureVector &data);
bool saveFile(QWidget *parent, const QJsonObject &json, const QString &defaultName);
bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64);
bool saveKeysToJsonFile(QWidget *parent, const QString &publicKey, const QString &privateKey, const QString &defaultName);
bool encryptAndSaveKey(QWidget *parent, const QString &privateKey, const unsigned char *derivedKey, QString username, bool (*saveFuncPtrArg)(const QString&, const SecureVector&));
bool encryptAndSaveMasterKey(const unsigned char *keyToEncrypt, size_t keyLen, const unsigned char *derivedKey, shared_ptr<EncryptionHelper> crypto, QString username);
SecureVector encryptData(const QByteArray &plaintext, unsigned char *key, unsigned char *nonce, shared_ptr<EncryptionHelper> crypto);
bool decryptAndReencryptUserFile(const QString& username, const QString& oldPassword, const QString& oldSalt, const QString& newPassword, const QString& newSalt);
bool decryptMasterKey(const QString& username, const QString& password, const QString& salt);

inline bool deriveKeyFromPassword(const string &password, const unsigned char *salt, unsigned char *key, size_t key_len= crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    unsigned long long opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    size_t memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;

    return crypto_pwhash(
               key, key_len,
               password.c_str(), password.size(),
               salt,
               opslimit, memlimit,
               crypto_pwhash_ALG_DEFAULT
               ) == 0;
}

inline QString generateSalt(size_t length = crypto_pwhash_SALTBYTES) {
    const size_t SALT_LENGTH = length;
    unsigned char salt[SALT_LENGTH];
    randombytes_buf(salt, SALT_LENGTH);

    QByteArray saltArray(reinterpret_cast<char*>(salt), SALT_LENGTH);
    QString saltBase64 = saltArray.toBase64();
    return saltBase64;
}

#endif // KEY_UTILS_H
