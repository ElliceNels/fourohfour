#include "key_utils.h"
#include "qjsondocument.h"
#include "qjsonobject.h"
#include <sodium.h>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <sodium.h>
#include <QByteArray>
#include <QString>
#include <QCoreApplication>
#include <iostream>
#include <vector>
#include <QByteArray>

using namespace std;

bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64) {
    if (sodium_init() < 0) {
        // libsodium couldn't be initialized
        return false;
    }

    unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char privateKey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(publicKey, privateKey);

    QByteArray pubKeyArray(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);
    QByteArray privKeyArray(reinterpret_cast<char*>(privateKey), crypto_box_SECRETKEYBYTES);

    publicKeyBase64 = pubKeyArray.toBase64();
    privateKeyBase64 = privKeyArray.toBase64();

    return true;
}

bool saveKeysToJsonFile(QWidget *parent, const QString &publicKey, const QString &privateKey, const QString &defaultName) {
    QJsonObject json;

    json["publicKey"] = publicKey;
    json["privateKey"] = privateKey;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();


    QString fileName = QFileDialog::getSaveFileName(parent, "Save Keys", defaultName, "JSON Files (*.json);;All Files (*)");
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            file.write(jsonData);
            file.close();
            return true;
        } else {
            QMessageBox::warning(parent, "Error", "Failed to open file for writing.");
        }
    }
    return false;
}


bool encryptAndSaveKey(QWidget *parent, const QString &privateKey, const unsigned char *derivedKey) {
    QJsonObject json;
    json["privateKey"] = privateKey;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();
    EncryptionHelper crypto;

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    // Generate key and nonce
    crypto.generateKey(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto.generateNonce(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    //Encrypt private key file
    vector<unsigned char> ciphertext;
    bool success = false;
    try {
        ciphertext = encryptData(jsonData, key, nonce, crypto);
    } catch (const std::exception &e) {
        QMessageBox::critical(parent, "Encryption Error", e.what());
        sodium_memzero(key, sizeof(key));
    }


    //Save encrypted private key file
    QString fileName = QCoreApplication::applicationDirPath() + "/encryptedKeys.bin";
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(reinterpret_cast<const char*>(ciphertext.data()), static_cast<qint64>(ciphertext.size()));
        file.close();
    } else {
        std::cout << "Error saving file" << std::endl;
        return false;
    }


    //Encrypt and save master key
    if(!encryptAndSaveMasterKey(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, derivedKey, crypto)){
        std::cout << "Error saving encrypted key file" << std::endl;
        sodium_memzero(key, sizeof(key));
        return false;
    }

    sodium_memzero(key, sizeof(key));
    return true;
}

bool encryptAndSaveMasterKey(const unsigned char *keyToEncrypt, size_t keyLen, const unsigned char *derivedKey, EncryptionHelper &crypto)
{
    // Generate nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    crypto.generateNonce(nonce, sizeof(nonce));

    // Encrypt the key
    vector<unsigned char> encryptedKey = crypto.encrypt(
        keyToEncrypt,
        keyLen,
        derivedKey,
        nonce,
        nullptr,
        0
        );

    // Prepare data: [nonce][encryptedKey]
    QByteArray outData(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    outData.append(reinterpret_cast<const char*>(encryptedKey.data()), static_cast<int>(encryptedKey.size()));

    // Save to file
    QString filePath = QCoreApplication::applicationDirPath() + "/masterKey.bin";
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(outData);
        file.close();
        return true;
    } else {
        return false;
    }
}


vector<unsigned char> encryptData(const QByteArray &plaintext, unsigned char *key, unsigned char *nonce, EncryptionHelper &crypto){

    const unsigned char* plaintext_ptr = reinterpret_cast<const unsigned char*>(plaintext.constData());
    unsigned long long plaintext_len = static_cast<unsigned long long>(plaintext.size());

    // Encrypt with no metadata
    return crypto.encrypt(
        plaintext_ptr,
        plaintext_len,
        key,
        nonce,
        nullptr,
        0
        );
}

QString generateSalt(size_t length){
    const size_t SALT_LENGTH = length;
    unsigned char salt[SALT_LENGTH];
    randombytes_buf(salt, SALT_LENGTH);

    // Convert to QString
    QByteArray saltArray(reinterpret_cast<char*>(salt), SALT_LENGTH);
    QString saltBase64 = saltArray.toBase64();
    return saltBase64;
}

bool deriveKeyFromPassword(const string &password, const unsigned char *salt, unsigned char *key, size_t key_len) {
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
