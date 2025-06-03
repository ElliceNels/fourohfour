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

/**
 * @brief Generates multiple one-time pre-key pairs for secure communication
 *
 * This function generates KEY_GEN_COUNT public/private key pairs using the X25519 elliptic-curve
 * Diffie-Hellman algorithm. These keys are used for secure file sharing between users.
 * The key pairs are generated, stored locally for future use, and the public keys
 * are returned to be uploaded to the server.
 *
 * @return QVector<QByteArray> A collection of public keys to be stored on the server, empty if failed
 *
 * @note The corresponding private keys are not returned but are securely stored locally
 * @see saveOneTimePreKeyPairsLocally()
 */
QVector<QByteArray> FileSharingUtils::generateOneTimePreKeyPairs() {
    QVector<QByteArray> publicKeys;
    QVector<QByteArray> privateKeys;
    
    // Reserve space for the number of keys to be generated
    publicKeys.reserve(KEY_GEN_COUNT);
    privateKeys.reserve(KEY_GEN_COUNT);

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
    bool savedSuccessfully = saveOneTimePreKeyPairsLocally(publicKeys, privateKeys);
    
    // Return the list of public keys only if successful, otherwise return empty vector
    return savedSuccessfully ? publicKeys : QVector<QByteArray>();
}

/**
 * @brief Securely stores one-time pre-key pairs on the local device
 *
 * This method encrypts and saves the provided public/private key pairs to the user's
 * local storage. The keys are encrypted using the user's master key and stored in a
 * JSON format for future use in secure file sharing operations.
 *
 * @param publicKeys Vector of public keys to be stored
 * @param privateKeys Vector of corresponding private keys to be stored
 * @return bool True if keys were successfully stored, false otherwise
 *
 * @note The keys are encrypted using XChaCha20-Poly1305 before being written to disk
 * @see generateOneTimePreKeyPairs()
 */
bool FileSharingUtils::saveOneTimePreKeyPairsLocally(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys) {
    // Validate inputs
    if (!validateKeyPairs(publicKeys, privateKeys)) {
        return false;
    }

    // Get master key and validate it
    const SecureVector masterKey = getMasterKey();
    if (masterKey.empty()) {
        return false; 
    }

    // Build file path for the key storage
    const QString filepath = buildKeyStorageFilePath();

    // Read existing encrypted file
    QByteArray jsonData;
    if (!readAndDecryptKeyStorage(filepath, masterKey, jsonData)) {
        return false;
    }
    
    // Create or update JSON structure with the prekeys
    QByteArray updatedJsonData;
    if (!updateJsonWithPrekeys(jsonData, publicKeys, privateKeys, updatedJsonData)) {
        return false;
    }
    
    // Encrypt and save the updated JSON data
    if (!encryptAndSaveKeyStorage(filepath, updatedJsonData, masterKey)) {
        return false;
    }
    
    qDebug() << "Successfully saved" << publicKeys.size() << "one-time prekey pairs";
    return true;
}

/**
 * @brief Validates that the provided key pairs are valid and matched
 *
 * @param publicKeys Vector of public keys to validate
 * @param privateKeys Vector of private keys to validate
 * @return bool True if the key pairs are valid, false otherwise
 */
bool FileSharingUtils::validateKeyPairs(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys) {
    if (publicKeys.isEmpty() || privateKeys.isEmpty() || publicKeys.size() != privateKeys.size()) {
        qWarning() << "Invalid key pairs provided for storage";
        return false;
    }
    return true;
}

/**
 * @brief Retrieves the user's master encryption key
 *
 * @return SecureVector The user's master key or empty vector if invalid
 */
SecureVector FileSharingUtils::getMasterKey() {
    const SecureVector masterKey = LoginSessionManager::getInstance().getMasterKey();
    if (masterKey.empty() || masterKey.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        qWarning() << "Invalid master key for encryption";
        return SecureVector();
    }
    return masterKey;
}

/**
 * @brief Constructs the file path for the key storage file
 *
 * @return QString Path to the user's key storage file
 */
QString FileSharingUtils::buildKeyStorageFilePath() {
    const QString username = LoginSessionManager::getInstance().getUsername();
    return QCoreApplication::applicationDirPath() + keysPath + username + binaryExtension;
}

/**
 * @brief Reads and decrypts the key storage file
 *
 * @param filepath Path to the encrypted key storage file
 * @param masterKey The user's master key for decryption
 * @param jsonData Output parameter that will contain the decrypted JSON data
 * @return bool True if successful, false otherwise
 */
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

/**
 * @brief Updates the JSON structure with new prekey pairs
 *
 * @param jsonData Existing JSON data (may be empty)
 * @param publicKeys Vector of public keys to add
 * @param privateKeys Vector of private keys to add
 * @param updatedJsonData Output parameter that will contain the updated JSON
 * @return bool True if successful, false otherwise
 */
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

/**
 * @brief Encrypts and saves the key storage data to a file
 *
 * @param filepath Path where the encrypted file should be saved
 * @param jsonData JSON data to encrypt and save
 * @param masterKey The user's master key for encryption
 * @return bool True if successful, false otherwise
 */
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