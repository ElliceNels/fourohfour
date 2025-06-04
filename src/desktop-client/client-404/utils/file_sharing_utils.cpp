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
#include "utils/file_crypto_utils.h"

/**
 * @brief Generates multiple one-time pre-key pairs for secure communication
 *
 * This function generates KEY_GEN_COUNT public/private key pairs using the X25519 elliptic-curve
 * Diffie-Hellman algorithm. These keys are used for secure file sharing between users.
 * The key pairs are generated, stored locally for future use, and the public keys
 * are returned as a JSON array of base64-encoded strings.
 *
 * @return QJsonArray A JSON array of base64-encoded public keys for storage on the server
 *
 * @note The corresponding private keys are not returned but are securely stored locally
 * @see saveOneTimePreKeyPairsLocally()
 */
QJsonArray FileSharingUtils::generateOneTimePreKeyPairs() {
    QVector<QByteArray> publicKeys;
    QVector<QByteArray> privateKeys;
    QJsonArray publicKeysJson;
    
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

        QByteArray publicKey(reinterpret_cast<char*>(pk.get()), crypto_box_PUBLICKEYBYTES);
        QByteArray privateKey(reinterpret_cast<char*>(sk.get()), crypto_box_SECRETKEYBYTES);
        
        publicKeys.append(publicKey);
        privateKeys.append(privateKey);
        
        // Add base64-encoded public key to JSON array
        publicKeysJson.append(QString(publicKey.toBase64()));
    }
    
    // Store these key pairs locally before returning
    bool savedSuccessfully = saveOneTimePreKeyPairsLocally(publicKeys, privateKeys);
    
    // Return the JSON array of base64-encoded public keys only if successful
    return savedSuccessfully ? publicKeysJson : QJsonArray();
}

/**
 * @brief Securely stores one-time pre-key pairs on the local device
 *
 * This method is now a wrapper around the more generic saveKeyPairsLocally method
 */
bool FileSharingUtils::saveOneTimePreKeyPairsLocally(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys) {
    return saveKeyPairsLocally("oneTimePrekeys", publicKeys, privateKeys);
}

/**
 * @brief Generic method to save key pairs of any type to local storage
 *
 * @param keyType Type identifier for the keys (e.g., "oneTimePrekeys", "signedPreKey", "ephemeral")
 * @param publicKeys Vector of public keys to be stored (can contain a single key)
 * @param privateKeys Vector of corresponding private keys to be stored
 * @return bool True if keys were successfully stored, false otherwise
 */
bool FileSharingUtils::saveKeyPairsLocally(const QString& keyType, const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys) {
    // Validate inputs
    if (!validateKeyPairs(publicKeys, privateKeys)) {
        return false;
    }

    // Get master key and validate it
    const SecureVector masterKey = LoginSessionManager::getInstance().getMasterKey();
    if (!FileCryptoUtils::validateMasterKey(masterKey)) {
        return false; 
    }

    // Build file path for the key storage
    const QString filepath = FileCryptoUtils::buildKeyStorageFilePath();

    // Read existing encrypted file
    QByteArray jsonData;
    if (!FileCryptoUtils::readAndDecryptKeyStorage(filepath, masterKey, jsonData)) {
        return false;
    }
    
    // Create or update JSON structure with the keys
    QByteArray updatedJsonData;
    if (!updateJsonWithKeysGeneric(jsonData, keyType, publicKeys, privateKeys, updatedJsonData)) {
        return false;
    }
    
    // Encrypt and save the updated JSON data
    if (!FileCryptoUtils::encryptAndSaveKeyStorage(filepath, updatedJsonData, masterKey)) {
        return false;
    }
    
    qDebug() << "Successfully saved" << publicKeys.size() << keyType << "key pairs";
    return true;
}

/**
 * @brief Saves a signed pre-key pair to local storage
 *
 * @param publicKeyBase64 Base64-encoded signed pre-key public key
 * @param privateKeyBase64 Base64-encoded signed pre-key private key
 * @return bool True if successful, false otherwise
 */
bool FileSharingUtils::saveSignedPreKeyLocally(const QString& publicKeyBase64, 
                                             const QString& privateKeyBase64) {
    QByteArray publicKey = QByteArray::fromBase64(publicKeyBase64.toUtf8());
    QByteArray privateKey = QByteArray::fromBase64(privateKeyBase64.toUtf8());
    
    return saveKeyPairsLocally("signedPreKey", QVector<QByteArray>{publicKey}, QVector<QByteArray>{privateKey});
}

/**
 * @brief Updates the JSON structure with new keys of any type
 *
 * @param jsonData Existing JSON data (may be empty)
 * @param keyType Type identifier for the keys
 * @param publicKeys Vector of public keys to add
 * @param privateKeys Vector of private keys to add
 * @param updatedJsonData Output parameter that will contain the updated JSON
 * @return bool True if successful, false otherwise
 */
bool FileSharingUtils::updateJsonWithKeysGeneric(const QByteArray &jsonData, 
                                              const QString& keyType,
                                              const QVector<QByteArray>& publicKeys, 
                                              const QVector<QByteArray>& privateKeys,
                                              QByteArray &updatedJsonData) {
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
    
    // Handle different key types appropriately
    if (keyType == "oneTimePrekeys") {
        // For one-time pre-keys, store as a dictionary with public key as the key and private key as the value
        QJsonObject preKeysObject = json.contains(keyType) ? 
                                    json[keyType].toObject() : 
                                    QJsonObject();
        
        for (int i = 0; i < publicKeys.size(); i++) {
            QString publicKeyBase64 = QString(publicKeys[i].toBase64());
            QString privateKeyBase64 = QString(privateKeys[i].toBase64());
            preKeysObject[publicKeyBase64] = privateKeyBase64;
        }
        
        json[keyType] = preKeysObject;
    }
    else if (keyType == "signedPreKey") {
        // For signed pre-keys, store as an object with public keys as indexes
        QJsonObject keyObject = json.contains(keyType) ?
                                json[keyType].toObject() :
                                QJsonObject();
        
        // Should only have one key of these types
        if (!publicKeys.isEmpty() && !privateKeys.isEmpty()) {
            QString publicKeyBase64 = QString(publicKeys[0].toBase64());
            QString privateKeyBase64 = QString(privateKeys[0].toBase64());
            
            // Store private key indexed by public key
            keyObject[publicKeyBase64] = privateKeyBase64;
        }
        
        json[keyType] = keyObject;
    }
    else if (keyType == "ephemeral") {
        // Ephemeral keys should never be stored - do nothing but warn
        qWarning() << "Attempt to store ephemeral keys was prevented for security reasons";
        // Return true to prevent errors when the function is called
        return true;
    }
    else {
        // Generic handling for other key types
        QJsonObject keysObject = json.contains(keyType) ?
                                json[keyType].toObject() :
                                QJsonObject();
        
        for (int i = 0; i < publicKeys.size(); i++) {
            QString publicKeyBase64 = QString(publicKeys[i].toBase64());
            QString privateKeyBase64 = QString(privateKeys[i].toBase64());
            
            keysObject[publicKeyBase64] = privateKeyBase64;
        }
        
        json[keyType] = keysObject;
    }
    
    // Prepare for encryption
    doc.setObject(json);
    updatedJsonData = doc.toJson(QJsonDocument::Compact);
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
    // First check: sizes of arrays must match and not be empty
    if (publicKeys.isEmpty() || privateKeys.isEmpty() || publicKeys.size() != privateKeys.size()) {
        qWarning() << "Invalid key pairs provided for storage";
        return false;
    }
    
    // Use constant-time validation to avoid timing attacks
    bool allValid = true;
    
    for (int i = 0; i < publicKeys.size(); i++) {
        // Use constant-time comparison for size validation
        bool validPublicKeySize = (publicKeys[i].size() == crypto_box_PUBLICKEYBYTES);
        bool validPrivateKeySize = (privateKeys[i].size() == crypto_box_SECRETKEYBYTES);
        
        // If any key fails validation, set allValid to false but continue processing
        // This ensures constant-time operation regardless of which key pair might be invalid
        if (!validPublicKeySize || !validPrivateKeySize) {
            allValid = false;
            qWarning() << "Key at index" << i << "has invalid size";
            // Don't break or return here to maintain constant time
        }
    }
    
    return allValid;
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

/**
 * @brief Generates a signed pre-key and its signature according to the X3DH protocol
 *
 * This function takes the user's Ed25519 identity key pair and generates a new X25519 
 * signed pre-key pair. It then creates a signature of the X25519 public key using 
 * the Ed25519 identity private key as specified in the X3DH protocol.
 *
 * @param identityPublicKeyBase64 Base64-encoded Ed25519 identity public key
 * @param identityPrivateKeyBase64 Base64-encoded Ed25519 identity private key
 * @param signedPreKeyPublic Output parameter for base64-encoded signed pre-key public key (X25519)
 * @param signedPreKeyPrivate Output parameter for base64-encoded signed pre-key private key (X25519)
 * @param signature Output parameter for base64-encoded signature (Ed25519)
 * @return bool True if successful (including key storage), false otherwise
 */
bool FileSharingUtils::generateSignedPreKey(const QString& identityPublicKeyBase64, const QString& identityPrivateKeyBase64, QString& signedPreKeyPublic, QString& signedPreKeyPrivate, QString& signature) {
   
    // Decode Ed25519 identity keys from base64
    QByteArray identityPublicKey = QByteArray::fromBase64(identityPublicKeyBase64.toUtf8());
    QByteArray identityPrivateKey = QByteArray::fromBase64(identityPrivateKeyBase64.toUtf8());
    
    // Validate Ed25519 identity keys
    if (identityPublicKey.size() != crypto_sign_PUBLICKEYBYTES ||
        identityPrivateKey.size() != crypto_sign_SECRETKEYBYTES) {
        qWarning() << "Invalid Ed25519 identity key length";
        return false;
    }
    
    // Generate a new X25519 key pair for the signed pre-key
    auto spk_x25519_pk = make_secure_buffer<crypto_box_PUBLICKEYBYTES>();
    auto spk_x25519_sk = make_secure_buffer<crypto_box_SECRETKEYBYTES>();
    
    if (crypto_box_keypair(spk_x25519_pk.get(), spk_x25519_sk.get()) != 0) {
        qWarning() << "Failed to generate signed pre-key pair";
        return false;
    }
    
    // Create signature of the signed pre-key public key
    // X3DH spec: Sig(IKB, Encode(SPKB))
    auto spk_signature = make_secure_buffer<crypto_sign_BYTES>();
    
    if (crypto_sign_detached(spk_signature.get(), nullptr, 
                             spk_x25519_pk.get(), crypto_box_PUBLICKEYBYTES,
                             reinterpret_cast<const unsigned char*>(identityPrivateKey.constData())) != 0) {
        qWarning() << "Failed to create signature of signed pre-key";
        return false;
    }
    
    // Convert results to base64
    signedPreKeyPublic = QByteArray(reinterpret_cast<char*>(spk_x25519_pk.get()), 
                                   crypto_box_PUBLICKEYBYTES).toBase64();
    signedPreKeyPrivate = QByteArray(reinterpret_cast<char*>(spk_x25519_sk.get()), 
                                    crypto_box_SECRETKEYBYTES).toBase64();
    signature = QByteArray(reinterpret_cast<char*>(spk_signature.get()), crypto_sign_BYTES).toBase64();
    
    // Add storage of the generated key pair automatically
    bool keySaved = saveSignedPreKeyLocally(signedPreKeyPublic, signedPreKeyPrivate);
    if (!keySaved) {
        qWarning() << "Failed to save signed pre-key locally";
        return false; // Return false if key storage fails
    }
    
    return true;
}

/**
 * @brief Verifies a signed pre-key signature according to X3DH protocol
 *
 * This function verifies that a signed pre-key was properly signed by the Ed25519 identity key.
 *
 * @param identityPublicKeyBase64 Base64-encoded Ed25519 identity public key
 * @param signedPreKeyPublicBase64 Base64-encoded X25519 signed pre-key public key
 * @param signatureBase64 Base64-encoded signature
 * @return bool True if signature is valid, false otherwise
 */
bool FileSharingUtils::verifySignedPreKey(const QString& identityPublicKeyBase64, const QString& signedPreKeyPublicBase64, const QString& signatureBase64) {
    // Decode from base64
    QByteArray identityPublicKey = QByteArray::fromBase64(identityPublicKeyBase64.toUtf8());
    QByteArray signedPreKeyPublic = QByteArray::fromBase64(signedPreKeyPublicBase64.toUtf8());
    QByteArray signature = QByteArray::fromBase64(signatureBase64.toUtf8());
    
    // Validate sizes - note the identity key is now Ed25519
    if (identityPublicKey.size() != crypto_sign_PUBLICKEYBYTES ||
        signedPreKeyPublic.size() != crypto_box_PUBLICKEYBYTES ||
        signature.size() != crypto_sign_BYTES) {
        qWarning() << "Invalid key or signature length for verification";
        return false;
    }
    
    // No conversion needed - directly use Ed25519 identity public key
    
    // Verify the signature
    int result = crypto_sign_verify_detached(
        reinterpret_cast<const unsigned char*>(signature.constData()),
        reinterpret_cast<const unsigned char*>(signedPreKeyPublic.constData()),
        signedPreKeyPublic.size(),
        reinterpret_cast<const unsigned char*>(identityPublicKey.constData())
    );
    
    if (result != 0) {
        qWarning() << "Signed pre-key signature verification failed with code:" << result;
        return false;
    }
    
    qDebug() << "Signed pre-key signature verified successfully";
    return true;
}

/**
 * @brief Generates an ephemeral key pair for use in X3DH protocol
 *
 * This function generates an X25519 ephemeral key pair (EKA in X3DH protocol)
 * which is used for a single protocol run to establish a shared secret key.
 * According to the X3DH specification, the ephemeral private key should be
 * used immediately and then deleted for forward secrecy.
 *
 * @param ephemeralPublicKey Output parameter for base64-encoded ephemeral public key
 * @param ephemeralPrivateKey Output parameter for base64-encoded ephemeral private key
 * @return bool True if successful, false otherwise
 */
bool FileSharingUtils::generateEphemeralKeyPair(QString& ephemeralPublicKey, QString& ephemeralPrivateKey) {
    // Generate a new X25519 key pair for the ephemeral key
    auto eph_x25519_pk = make_secure_buffer<crypto_box_PUBLICKEYBYTES>();
    auto eph_x25519_sk = make_secure_buffer<crypto_box_SECRETKEYBYTES>();
    
    if (crypto_box_keypair(eph_x25519_pk.get(), eph_x25519_sk.get()) != 0) {
        qWarning() << "Failed to generate ephemeral key pair";
        return false;
    }
    
    // Convert results to base64 and pass back via reference parameters
    ephemeralPublicKey = QByteArray(reinterpret_cast<char*>(eph_x25519_pk.get()), 
                                   crypto_box_PUBLICKEYBYTES).toBase64();
    ephemeralPrivateKey = QByteArray(reinterpret_cast<char*>(eph_x25519_sk.get()), 
                                    crypto_box_SECRETKEYBYTES).toBase64();
    
    qDebug() << "Ephemeral key pair generated successfully - NOT stored locally for forward secrecy";
    return true;
}

/**
 * @brief Helper method to extract a key from JSON storage
 * 
 * @param rootObject The JSON object containing key storage
 * @param keyType The type of key to extract (e.g., "signedPreKey", "oneTimePrekeys")
 * @param keyIdentifier The identifier (usually a public key) used to look up the private key
 * @param extractedKey Output parameter for the extracted key
 * @return bool True if key was found, false otherwise
 */
bool FileSharingUtils::extractKeyFromStorage(const QJsonObject& rootObject, 
                                          const QString& keyType, 
                                          const QString& keyIdentifier,
                                          QString& extractedKey) {
    if (rootObject.contains(keyType) && rootObject[keyType].isObject()) {
        QJsonObject keysObject = rootObject[keyType].toObject();
        
        if (keysObject.contains(keyIdentifier)) {
            extractedKey = keysObject[keyIdentifier].toString();
            qDebug() << "Found private" << keyType;
            return true;
        } else {
            qWarning() << "Private" << keyType << "not found for" << keyIdentifier;
            return false;
        }
    } else {
        qWarning() << "No" << keyType << "section found in key storage";
        return false;
    }
}

/**
 * @brief Retrieves Recipient's private key material necessary for X3DH key agreement
 *
 * This function retrieves the private keys corresponding to the provided public keys
 * from the local encrypted key storage file. These keys are used for Recipient's side of
 * the X3DH protocol to establish a shared secret with the Sender.
 *
 * @param publicSignedPreKeyBase64 Base64-encoded public signed pre-key used as index
 * @param publicOneTimePreKeyBase64 Base64-encoded public one-time pre-key used as index (mandatory)
 * @param privateSignedPreKey Output parameter for the retrieved private signed pre-key
 * @param privateOneTimePreKey Output parameter for the retrieved private one-time pre-key
 * @param privateKey Output parameter for the identity private key
 * @return bool True if all keys were successfully retrieved, false otherwise
 */
bool FileSharingUtils::retrieveRecipientKeyMaterialForX3DH(
    const QString& publicSignedPreKeyBase64,
    const QString& publicOneTimePreKeyBase64,
    QString& privateSignedPreKey,
    QString& privateOneTimePreKey,
    QString& privateKey) {
    
    // Validate input parameters - both signed pre-key and one-time pre-key are required
    if (publicSignedPreKeyBase64.isEmpty()) {
        qWarning() << "Empty signed pre-key provided";
        return false;
    }
    
    if (publicOneTimePreKeyBase64.isEmpty()) {
        qWarning() << "Empty one-time pre-key provided";
        return false;
    }
    
    // Get master key and validate it
    const SecureVector masterKey = getMasterKey();
    if (masterKey.empty()) {
        qWarning() << "Failed to retrieve master key for key material retrieval";
        return false;
    }
    
    // Build file path for the key storage
    const QString filepath = buildKeyStorageFilePath();
    
    // Read and decrypt key storage file
    QByteArray jsonData;
    if (!readAndDecryptKeyStorage(filepath, masterKey, jsonData)) {
        qWarning() << "Failed to read and decrypt key storage file";
        return false;
    }
    
    // Parse JSON data
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        qWarning() << "Failed to parse key storage JSON:" << parseError.errorString();
        return false;
    }
    
    QJsonObject rootObject = doc.object();
    bool allKeysFound = true;
    
    // Extract all required keys using the helper method
    allKeysFound &= extractKeyFromStorage(rootObject, "signedPreKey", publicSignedPreKeyBase64, privateSignedPreKey);
    
    // One-time pre-key is mandatory in this implementation
    allKeysFound &= extractKeyFromStorage(rootObject, "oneTimePrekeys", publicOneTimePreKeyBase64, privateOneTimePreKey);
    // Note: We keep the one-time pre-key for future file decryption needs
    
    // Identity private key is stored differently, direct in the root
    if (rootObject.contains("privateKey") && rootObject["privateKey"].isString()) {
        privateKey = rootObject["privateKey"].toString();
        qDebug() << "Found identity private key";
    } else {
        qWarning() << "Identity private key not found in key storage";
        allKeysFound = false;
    }
    
    return allKeysFound;
}