#include "key_utils.h"
#include <qjsondocument.h>
#include <qjsonobject.h>
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
#include "core/loginsessionmanager.h"
#include "utils/securebufferutils.h"
#include "utils/securevector.h"


using namespace std;

bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64) {

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

    //Function pointer
    bool (*saveFuncPtr)(QWidget*, const QJsonObject&, const QString&) = saveFile;

    return saveFuncPtr(parent, json, defaultName);
}


bool encryptAndSaveKey(QWidget *parent, const QString &privateKey, const unsigned char *derivedKey, QString username) {
    QJsonObject json;
    json["privateKey"] = privateKey;

    // Print derivedKey in base64 format
    QByteArray keyArray(reinterpret_cast<const char*>(derivedKey), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    cout << "Derived Key (base64): " << keyArray.toBase64().toStdString() << endl;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    shared_ptr<EncryptionHelper> crypto = make_shared<EncryptionHelper>();

    auto key = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();

    // Generate key and nonce
    crypto->generateKey(key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto->generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    //Encrypt private key file
    SecureVector ciphertext;
    bool success = false;
    try {
        ciphertext = encryptData(jsonData, key.get(), nonce.get(), crypto);
    } catch (const exception &e) {
        QMessageBox::critical(parent, "Encryption Error", e.what());
    }

    // Prepare data: [nonce][ciphertext]
    SecureVector combinedData(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + ciphertext.size());
    std::copy(nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, combinedData.begin());    // Copies the nonce to the start of the buffer
    std::copy(ciphertext.data(), ciphertext.data() + ciphertext.size(),  combinedData.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES); // Copy the ciphertext to the buffer right after the nonce

    //Save encrypted private key file
    QString fileName = QCoreApplication::applicationDirPath() + keysPath + username + binaryExtension; //encryptedKey_username.bin
    bool (*saveFuncPtr)(const QString&, const SecureVector&) = saveFile; //function pointer
    if (!saveFuncPtr(fileName, combinedData)) {
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

bool encryptAndSaveMasterKey(const unsigned char *keyToEncrypt, size_t keyLen, const unsigned char *derivedKey, shared_ptr<EncryptionHelper> crypto, QString username)
{
    // Generate nonce
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    crypto->generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);


    // Encrypt the key
    SecureVector encryptedKey = crypto->encrypt(
        keyToEncrypt,
        keyLen,
        derivedKey,
        nonce.get(),
        nullptr,
        0
        );

    // Prepare data: [nonce][encryptedKey]
    SecureVector combinedData(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + encryptedKey.size());
    std::copy(nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, combinedData.begin());    // Copies the nonce to the start of the buffer
    std::copy(encryptedKey.data(), encryptedKey.data() + encryptedKey.size(), combinedData.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);  // Copy the ciphertext to the buffer right after the nonce

    // Save to file
    QString filePath = QCoreApplication::applicationDirPath() + masterKeyPath + username + binaryExtension;//masterKey.bin;
    bool (*saveFuncPtr)(const QString&, const SecureVector&) = saveFile; //function pointer
    bool success = saveFuncPtr(filePath, combinedData);
    return success;
}


SecureVector encryptData(const QByteArray &plaintext, unsigned char *key, unsigned char *nonce, shared_ptr<EncryptionHelper> crypto){

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

bool decryptAndReencryptUserFile(const QString& username, const QString& oldPassword, const QString& oldSalt, const QString& newPassword, const QString& newSalt)
{
    shared_ptr<EncryptionHelper> crypto = make_shared<EncryptionHelper>();

    //Read encrypted file
    QString filePath = QCoreApplication::applicationDirPath() + masterKeyPath + username + binaryExtension;
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Failed to open file for reading:" << filePath;
        return false;
    }
    QByteArray encryptedData = file.readAll();
    file.close();

    //Extract nonce and ciphertext
    const int nonceSize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    QByteArray nonce = encryptedData.left(nonceSize);  // Get nonce from start
    QByteArray ciphertext = encryptedData.mid(nonceSize);  // Get ciphertext after nonce

    //Derive old key
    QByteArray oldSaltRaw = QByteArray::fromBase64(oldSalt.toUtf8());
    unsigned char oldKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    deriveKeyFromPassword(oldPassword.toStdString(), reinterpret_cast<const unsigned char*>(oldSaltRaw.constData()), oldKey, sizeof(oldKey));

    // Print oldKey in base64 format
    QByteArray keyArray(reinterpret_cast< const char*>(oldKey), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    cout << "Old Key (base64): " << keyArray.toBase64().toStdString() << endl;


    //Decrypt
    SecureVector decryptedData;
    try {
        decryptedData = crypto->decrypt(
            reinterpret_cast<const unsigned char*>(ciphertext.constData()), ciphertext.size(),
            oldKey,
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            nullptr, // no additional data
            0
            );
    } catch (const std::exception& e) {
        qDebug() << "Decryption failed:" << e.what();
        return false;
    }

    //Derive new key
    QByteArray newSaltRaw = QByteArray::fromBase64(newSalt.toUtf8());
    unsigned char newKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    deriveKeyFromPassword(newPassword.toStdString(), reinterpret_cast<const unsigned char*>(newSaltRaw.constData()), newKey, sizeof(newKey));

    return encryptAndSaveMasterKey(decryptedData.data(), decryptedData.size(), newKey, crypto, username);



}


//Function overloading
bool saveFile(const QString &filePath, const SecureVector &data) {
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
