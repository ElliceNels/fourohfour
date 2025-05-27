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
#include "securebufferutils.h"
#include "securevector.h"


using namespace std;

bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64) {
    if (sodium_init() < 0) {
        // libsodium couldn't be initialized
        return false;
    }

    auto publicKey = make_secure_buffer<crypto_box_PUBLICKEYBYTES>();
    auto privateKey = make_secure_buffer<crypto_box_SECRETKEYBYTES>();

    crypto_box_keypair(publicKey.get(), privateKey.get());


    QByteArray pubKeyArray(reinterpret_cast<char*>(publicKey.get()), crypto_box_PUBLICKEYBYTES);
    QByteArray privKeyArray(reinterpret_cast<char*>(privateKey.get()), crypto_box_SECRETKEYBYTES);

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


bool encryptAndSaveKey(QWidget *parent, const QString &privateKey, const unsigned char *derivedKey, QString username) {
    QJsonObject json;
    json["privateKey"] = privateKey;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();
    EncryptionHelper crypto;

    auto key = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();

    // Generate key and nonce
    crypto.generateKey(key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto.generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    //Encrypt private key file
    SecureVector ciphertext;
    bool success = false;
    try {
        ciphertext = encryptData(jsonData, key.get(), nonce.get(), crypto);
    } catch (const exception &e) {
        QMessageBox::critical(parent, "Encryption Error", e.what());
    }

    // Prepare data: [ciphertext][nonce]
    ciphertext.insert(ciphertext.end(), nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    //Save encrypted private key file
    QString fileName = QCoreApplication::applicationDirPath() + keysPath + username + binaryExtension; //encryptedKey_username.bin
    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(reinterpret_cast<const char*>(ciphertext.data()), static_cast<qint64>(ciphertext.size())); //convert to raw bytes
        file.close();
    } else {
        cout << "Error saving file" << endl;
        jsonData.fill(0);
        jsonData.clear();
        return false;
    }

    //clear data
    jsonData.fill(0);
    jsonData.clear();


    //Encrypt and save master key
    if(!encryptAndSaveMasterKey(key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES, derivedKey, crypto, username)){
        cout << "Error saving encrypted key file" << endl;
        return false;
    }

    LoginSessionManager::getInstance().setSession(username, key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    return true;
}

bool encryptAndSaveMasterKey(const unsigned char *keyToEncrypt, size_t keyLen, const unsigned char *derivedKey, EncryptionHelper &crypto, QString username)
{
    // Generate nonce
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();

    crypto.generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);


    // Encrypt the key
    SecureVector encryptedKey = crypto.encrypt(
        keyToEncrypt,
        keyLen,
        derivedKey,
        nonce.get(),
        nullptr,
        0
        );

    // Prepare data: [encryptedKey][nonce]

    encryptedKey.insert(encryptedKey.end(), nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Save to file
    QString filePath = QCoreApplication::applicationDirPath() + masterKeyPath + username + binaryExtension;//masterKey.bin;
    QFile file(filePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(reinterpret_cast<const char*>(encryptedKey.data()), static_cast<qint64>(encryptedKey.size()));
        file.close();
        return true;
    } else {
        return false;
    }
}


SecureVector encryptData(const QByteArray &plaintext, unsigned char *key, unsigned char *nonce, EncryptionHelper &crypto){

    const unsigned char* plaintext_ptr;
    unsigned long long plaintext_len;
    try {
        plaintext_ptr = reinterpret_cast<const unsigned char*>(plaintext.constData());
        plaintext_len = static_cast<unsigned long long>(plaintext.size());
    } catch (const exception& e) {
        qWarning() << "Exception:" << e.what();
    }

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
    SecureVector salt(SALT_LENGTH);
    randombytes_buf(salt.data(), SALT_LENGTH);


    // Convert to QString
    QByteArray saltArray(reinterpret_cast<char*>(salt.data()), SALT_LENGTH);
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
