#include "file_sharing_utils.h"
#include <QDebug>
#include <QApplication>
#include <sodium.h>
#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QCoreApplication>
#include "core/loginsessionmanager.h"
#include "crypto/encryptionhelper.h"
#include "utils/securebufferutils.h"
#include "constants.h"

QVector<QByteArray> FileSharingUtils::generateOneTimePreKeyPairs() {
    QVector<QByteArray> publicKeys;
    QVector<QByteArray> privateKeys;

    for (int i = 0; i < KEY_GEN_COUNT; ++i) {
   
        auto pk = make_secure_buffer<crypto_box_PUBLICKEYBYTES>();
        auto sk = make_secure_buffer<crypto_box_SECRETKEYBYTES>();

        // generates a key pair using the X25519 algorithm, which is an elliptic-curve Diffie-Hellman (ECDH) function based on Curve25519
        if (crypto_box_keypair(pk.get(), sk.get()) != 0) {
            qWarning() << "Key generation failed at index" << i;
            continue;
        }

        publicKeys.append(QByteArray(reinterpret_cast<char*>(pk.get()), crypto_box_PUBLICKEYBYTES));
        privateKeys.append(QByteArray(reinterpret_cast<char*>(sk.get()), crypto_box_SECRETKEYBYTES));
    }
    
    // Store these key pairs locally before returning
    saveOneTimePreKeyPairsLocally(publicKeys, privateKeys);
    
    // Return the list of public keys to be stored server-side
    return publicKeys; 
}

void FileSharingUtils::saveOneTimePreKeyPairsLocally(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys){
    // Validate inputs
    if (!validateKeyPairs(publicKeys, privateKeys)) {
        return;
    }

    // Get master key and validate it
    const SecureVector masterKey = getMasterKey();
    if (masterKey.empty()) {
        return; 
    }

    // Build file path for the key storage
    const QString filepath = buildKeyStorageFilePath();

    // Read existing encrypted file
    QByteArray jsonData;
    if (!readAndDecryptKeyStorage(filepath, masterKey, jsonData)) {
        return;
    }
    
    // Create or update JSON structure with the prekeys
    QByteArray updatedJsonData;
    if (!updateJsonWithPrekeys(jsonData, publicKeys, privateKeys, updatedJsonData)) {
        return;
    }
    
    // Encrypt and save the updated JSON data
    if (!encryptAndSaveKeyStorage(filepath, updatedJsonData, masterKey)) {
        return;
    }
    
    qDebug() << "Successfully saved" << publicKeys.size() << "one-time prekey pairs";
}

bool FileSharingUtils::validateKeyPairs(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys) {
    if (publicKeys.isEmpty() || privateKeys.isEmpty() || publicKeys.size() != privateKeys.size()) {
        qWarning() << "Invalid key pairs provided for storage";
        return false;
    }
    return true;
}

SecureVector FileSharingUtils::getMasterKey() {
    const SecureVector masterKey = LoginSessionManager::getInstance().getMasterKey();
    if (masterKey.empty() || masterKey.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        qWarning() << "Invalid master key for encryption";
        return SecureVector();
    }
    return masterKey;
}

QString FileSharingUtils::buildKeyStorageFilePath() {
    const QString username = LoginSessionManager::getInstance().getUsername();
    return QCoreApplication::applicationDirPath() + keysPath + username + binaryExtension;
}

bool FileSharingUtils::readAndDecryptKeyStorage(const QString &filepath, const SecureVector &masterKey, QByteArray &jsonData) {
    
    QFile file(filepath);
    
    // if the file doesn't exist, we create an empty new one
    if (!file.exists()) {
        jsonData = QByteArray();
        return true;
    }
    
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Failed to open encrypted keys file:" << file.errorString();
        return false;
    }
    
    const QByteArray fileData = file.readAll();
    file.close();
    
    // Validate file data
    if (fileData.size() <= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        qWarning() << "Encrypted file is too small or corrupted";
        return false;
    }
    
    // Extract nonce and ciphertext
    const int ciphertextSize = fileData.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    SecureVector ciphertext(ciphertextSize);
    
    std::copy(fileData.constData(), fileData.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, nonce.get());
    std::copy(fileData.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, fileData.constData() + fileData.size(), ciphertext.begin());
    
    // Decrypt data
    EncryptionHelper crypto;
    try {
        SecureVector plaintext = crypto.decrypt(
            ciphertext.data(),
            ciphertextSize,
            masterKey.data(),
            nonce.get(),
            nullptr,
            0
        );
        
        jsonData = QByteArray(reinterpret_cast<const char*>(plaintext.data()), static_cast<int>(plaintext.size()));
        return true;
    } catch (const std::exception& e) {
        qWarning() << "Decryption failed:" << e.what();
        return false;
    }
}

bool FileSharingUtils::updateJsonWithPrekeys(const QByteArray &jsonData, const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys, QByteArray &updatedJsonData) {
    // Parse or create JSON structure
    QJsonDocument doc;
    if (!jsonData.isEmpty()) {
        QJsonParseError parseError;
        doc = QJsonDocument::fromJson(jsonData, &parseError);
        
        if (parseError.error != QJsonParseError::NoError) {
            qWarning() << "Failed to parse JSON:" << parseError.errorString();
            return false;
        }
    }
    
    QJsonObject json = doc.isObject() ? doc.object() : QJsonObject();
    
    // Create oneTimePreKeys object (dictionary)
    QJsonObject preKeysObject;
    
    // Add each key pair to the object with public key as the key and private key as the value
    for (int i = 0; i < publicKeys.size(); i++) {
        QString publicKeyBase64 = QString(publicKeys[i].toBase64());
        QString privateKeyBase64 = QString(privateKeys[i].toBase64());
        preKeysObject[publicKeyBase64] = privateKeyBase64;
    }
    
    // Store in JSON with proper camelCase naming
    json["oneTimePrekeys"] = preKeysObject;
    
    // Prepare for encryption
    doc.setObject(json);
    updatedJsonData = doc.toJson(QJsonDocument::Compact);
    return true;
}

bool FileSharingUtils::encryptAndSaveKeyStorage(const QString &filepath, const QByteArray &jsonData, const SecureVector &masterKey) {
    // Encrypt and save
    EncryptionHelper crypto;
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    crypto.generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    
    SecureVector ciphertext = crypto.encrypt(
        reinterpret_cast<const unsigned char*>(jsonData.constData()),
        jsonData.size(),
        masterKey.data(),
        nonce.get(),
        nullptr,
        0
    );
    
    // Combine nonce and ciphertext
    SecureVector combinedData(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + ciphertext.size());
    std::copy(nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, combinedData.begin());
    std::copy(ciphertext.data(), ciphertext.data() + ciphertext.size(), combinedData.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    
    // Save to file
    QFile file(filepath);
    if (!file.open(QIODevice::WriteOnly)) {
        qWarning() << "Failed to open file for writing:" << file.errorString();
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(combinedData.data()), static_cast<qint64>(combinedData.size()));
    file.close();
    
    return true;
}