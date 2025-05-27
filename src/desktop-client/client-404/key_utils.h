#ifndef KEY_UTILS_H
#define KEY_UTILS_H

#include <QString>
#include <QWidget>
#include "encryptionhelper.h"
using namespace std;


bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64);
bool saveKeysToJsonFile(QWidget *parent, const QString &publicKey, const QString &privateKey, const QString &defaultName);
bool encryptAndSaveKey(QWidget *parent, const QString &privateKey, const unsigned char *derivedKey, QString username);
bool encryptAndSaveMasterKey(const unsigned char *keyToEncrypt, size_t keyLen, const unsigned char *derivedKey, EncryptionHelper &crypto, QString username);
SecureVector encryptData(const QByteArray &plaintext, unsigned char *key, unsigned char *nonce, EncryptionHelper &crypto);
bool deriveKeyFromPassword(const string &password, const unsigned char *salt, unsigned char *key, size_t key_len);
QString generateSalt(size_t length);

#endif // KEY_UTILS_H
