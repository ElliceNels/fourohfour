#include "key_utils.h"
#include "qjsondocument.h"
#include "qjsonobject.h"
#include <sodium.h>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <QByteArray>
#include <QString>
#include <QCoreApplication>
#include <iostream>
#include <vector>
#include "constants.h"
#include "loginsessionmanager.h"

using namespace std;

bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64) {

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

    //Function pointer
    bool (*saveFuncPtr)(QWidget*, const QJsonObject&, const QString&) = saveFile;

    return saveFuncPtr(parent, json, defaultName);
}


bool encryptAndSaveKey(QWidget *parent, const QString &privateKey, const unsigned char *derivedKey, QString username) {
    QJsonObject json;
    json["privateKey"] = privateKey;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    shared_ptr<EncryptionHelper> crypto = make_shared<EncryptionHelper>();

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    // Generate key and nonce
    crypto->generateKey(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto->generateNonce(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    //Encrypt private key file
    vector<unsigned char> ciphertext;
    bool success = false;
    try {
        ciphertext = encryptData(jsonData, key, nonce, crypto);
    } catch (const exception &e) {
        QMessageBox::critical(parent, "Encryption Error", e.what());
        sodium_memzero(key, sizeof(key));
    }

    // Prepare data: [ciphertext][nonce]
    ciphertext.insert(ciphertext.end(), nonce, nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    //Save encrypted private key file
    QString fileName = QCoreApplication::applicationDirPath() + keysPath + username + binaryExtension; //encryptedKey_username.bin
    bool (*saveFuncPtr)(const QString&, const std::vector<unsigned char>&) = saveFile; //function pointer
    if (!saveFuncPtr(fileName, ciphertext)) {
        cout << "Error saving file" << endl;
        jsonData.fill(0);
        jsonData.clear();

        fill(ciphertext.begin(), ciphertext.end(), 0);
        ciphertext.clear();
        return false;
    }

    //clear data
    jsonData.fill(0);
    jsonData.clear();

    fill(ciphertext.begin(), ciphertext.end(), 0);
    ciphertext.clear();


    //Encrypt and save master key
    if(!encryptAndSaveMasterKey(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, derivedKey, crypto, username)){
        cout << "Error saving encrypted key file" << endl;
        sodium_memzero(key, sizeof(key));
        return false;
    }

    LoginSessionManager::getInstance().setSession(username, key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    sodium_memzero(key, sizeof(key));
    return true;
}

bool encryptAndSaveMasterKey(const unsigned char *keyToEncrypt, size_t keyLen, const unsigned char *derivedKey, shared_ptr<EncryptionHelper> crypto, QString username)
{
    // Generate nonce
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    crypto->generateNonce(nonce, sizeof(nonce));

    // Encrypt the key
    vector<unsigned char> encryptedKey = crypto->encrypt(
        keyToEncrypt,
        keyLen,
        derivedKey,
        nonce,
        nullptr,
        0
        );

    // Prepare data: [encryptedKey][nonce]
    encryptedKey.insert(encryptedKey.end(), nonce, nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Save to file
    QString filePath = QCoreApplication::applicationDirPath() + masterKeyPath + username + binaryExtension;//masterKey.bin;
    bool (*saveFuncPtr)(const QString&, const std::vector<unsigned char>&) = saveFile; //function pointer
    bool success = saveFuncPtr(filePath, encryptedKey);
    fill(encryptedKey.begin(), encryptedKey.end(), 0);
    encryptedKey.clear();
    return success;
}


vector<unsigned char> encryptData(const QByteArray &plaintext, unsigned char *key, unsigned char *nonce, shared_ptr<EncryptionHelper> crypto){

    const unsigned char* plaintext_ptr;
    unsigned long long plaintext_len;
    try {
        plaintext_ptr = reinterpret_cast<const unsigned char*>(plaintext.constData());
        plaintext_len = static_cast<unsigned long long>(plaintext.size());
    } catch (const exception& e) {
        qWarning() << "Exception:" << e.what();
    }

    // Encrypt with no metadata
    return crypto->encrypt(
        plaintext_ptr,
        plaintext_len,
        key,
        nonce,
        nullptr,
        0
        );
}

//Function overloading
bool saveFile(const QString &filePath, const std::vector<unsigned char> &data) {
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<qint64>(data.size()));
        file.close();
        return true;
    }
    return false;
}

bool saveFile(QWidget *parent, const QJsonObject &json, const QString &defaultName) {
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


