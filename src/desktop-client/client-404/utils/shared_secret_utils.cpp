#include "shared_secret_utils.h"
#include <QDebug>
#include <sodium.h>
#include <QByteArray>
#include <QMessageBox>
#include "utils/file_sharing_utils.h"
#include "utils/x3dh_network_utils.h"
#include "crypto/encryptionhelper.h"
#include "utils/securebufferutils.h"
#include "utils/friend_storage_utils.h"
#include "core/loginsessionmanager.h"
#include "utils/file_crypto_utils.h"

/**
 * @brief Shows an error message if parent widget is available
 */
void SharedSecretUtils::showErrorMessage(QWidget* parent, const QString& title, const QString& message) {
    if (parent) {
        QMessageBox::warning(parent, title, message);
    }
    qWarning() << title << ":" << message;
}

/**
 * @brief Generates a shared secret key for the recipient according to X3DH protocol
 */
SecureVector SharedSecretUtils::generateRecipientSharedSecret(
    const QString& senderIdentityKeyBase64,
    const QString& senderEphemeralKeyBase64, 
    const QString& recipientSignedPreKeyBase64,
    const QString& oneTimePreKeyBase64,
    bool removeUsedOneTimePreKey,
    QWidget* parent) {
    
    // Validate inputs
    if (senderIdentityKeyBase64.isEmpty() || senderEphemeralKeyBase64.isEmpty() || 
        recipientSignedPreKeyBase64.isEmpty() || oneTimePreKeyBase64.isEmpty()) {
        showErrorMessage(parent, "Key Error", "Required keys missing for shared secret generation");
        return SecureVector();
    }
    
    // Retrieve recipient's private keys using FileSharingUtils method
    QString privateSignedPreKey;
    QString privateOneTimePreKey;
    QString privateIdentityKey;  // This is Ed25519 format
    
    bool keysRetrieved = FileSharingUtils::retrieveRecipientKeyMaterialForX3DH(
        recipientSignedPreKeyBase64,
        oneTimePreKeyBase64,
        privateSignedPreKey,
        privateOneTimePreKey,
        privateIdentityKey
    );
    
    if (!keysRetrieved) {
        showErrorMessage(parent, "Key Error", "Failed to retrieve recipient's private keys for shared secret generation");
        return SecureVector();
    }
    
    // Verify one-time prekey was retrieved (mandatory in our implementation)
    if (privateOneTimePreKey.isEmpty()) {
        showErrorMessage(parent, "Key Error", "One-time prekey is mandatory but was not retrieved successfully");
        return SecureVector();
    }
    
    // Convert Ed25519 keys to X25519 for Diffie-Hellman operations
    QString senderIdentityKeyX25519Base64;
    QString recipientIdentityKeyX25519Base64;
    
    if (!convertEd25519ToX25519Keys(
            senderIdentityKeyBase64, // Public key input
            privateIdentityKey,      // Private key input
            senderIdentityKeyX25519Base64,  // Public key output
            recipientIdentityKeyX25519Base64)) { // Private key output
        
        showErrorMessage(parent, "Conversion Error", "Failed to convert Ed25519 identity keys to X25519");
        return SecureVector();
    }
    
    // Calculate DH outputs according to X3DH protocol
    QVector<SecureVector> dhOutputs;
    
    // DH1 = DH(SPKB_private, IKA_public)
    // Bob uses his signed prekey private key with Alice's identity public key
    SecureVector dh1 = performDH(privateSignedPreKey, senderIdentityKeyX25519Base64);
    if (dh1.empty()) {
        showErrorMessage(parent, "DH Error", "DH1 calculation failed");
        return SecureVector();
    }
    dhOutputs.append(dh1);
    
    // DH2 = DH(IKB_private, EKA_public)
    // Bob uses his identity private key with Alice's ephemeral public key
    SecureVector dh2 = performDH(recipientIdentityKeyX25519Base64, senderEphemeralKeyBase64);
    if (dh2.empty()) {
        showErrorMessage(parent, "DH Error", "DH2 calculation failed");
        return SecureVector();
    }
    dhOutputs.append(dh2);
    
    // DH3 = DH(SPKB_private, EKA_public)
    // Bob uses his signed prekey private key with Alice's ephemeral public key
    SecureVector dh3 = performDH(privateSignedPreKey, senderEphemeralKeyBase64);
    if (dh3.empty()) {
        showErrorMessage(parent, "DH Error", "DH3 calculation failed");
        return SecureVector();
    }
    dhOutputs.append(dh3);
    
    // DH4 = DH(OPKB_private, EKA_public)
    // Bob uses his one-time prekey private key with Alice's ephemeral public key
    SecureVector dh4 = performDH(privateOneTimePreKey, senderEphemeralKeyBase64);
    if (dh4.empty()) {
        showErrorMessage(parent, "DH Error", "DH4 calculation failed");
        return SecureVector();
    }
    dhOutputs.append(dh4);
    
    // Apply KDF to derive the shared secret
    SecureVector sharedSecret = applyKDF(dhOutputs);
    
    // Clean up DH outputs for security
    for (auto& output : dhOutputs) {
        sodium_memzero(output.data(), output.size());
    }
    
    // Remove one-time prekey if specified
    if (removeUsedOneTimePreKey) {
        if (!FileSharingUtils::removeOneTimePreKey(oneTimePreKeyBase64)) {
            qWarning() << "Failed to remove used one-time prekey, but continuing with shared secret";
        }
    }
    
    qDebug() << "Successfully generated recipient's shared secret";
    return sharedSecret;
}

/**
 * @brief Performs a Diffie-Hellman key exchange using X25519
 */
SecureVector SharedSecretUtils::performDH(const QString& privateKeyBase64, 
                                        const QString& publicKeyBase64) {
    // Decode base64 keys to byte arrays
    QByteArray privateKeyBytes = QByteArray::fromBase64(privateKeyBase64.toUtf8());
    QByteArray publicKeyBytes = QByteArray::fromBase64(publicKeyBase64.toUtf8());
    
    // Validate key sizes
    if (privateKeyBytes.size() != crypto_scalarmult_curve25519_SCALARBYTES || 
        publicKeyBytes.size() != crypto_scalarmult_curve25519_BYTES) {
        qWarning() << "Invalid key size for DH operation";
        return SecureVector();
    }
    
    // Use secure buffers for input keys
    auto privateBuf = make_secure_buffer<crypto_scalarmult_curve25519_SCALARBYTES>();
    auto publicBuf = make_secure_buffer<crypto_scalarmult_curve25519_BYTES>();
    
    // Copy the key data into secure buffers
    std::memcpy(privateBuf.get(), privateKeyBytes.constData(), crypto_scalarmult_curve25519_SCALARBYTES);
    std::memcpy(publicBuf.get(), publicKeyBytes.constData(), crypto_scalarmult_curve25519_BYTES);
    
    // Create secure buffer for the output
    SecureVector output(crypto_scalarmult_curve25519_BYTES);
    
    // Perform X25519 scalar multiplication
    if (crypto_scalarmult_curve25519(
            output.data(),
            privateBuf.get(),
            publicBuf.get()) != 0) {
        qWarning() << "Diffie-Hellman calculation failed";
        return SecureVector();
    }
    
    return output;
}

/**
 * @brief Applies the KDF to derive a shared secret key
 */
SecureVector SharedSecretUtils::applyKDF(const QVector<SecureVector>& dhOutputs) {
    if (dhOutputs.isEmpty()) {
        qWarning() << "No DH outputs provided for KDF";
        return SecureVector();
    }
    
    // Calculate the total size needed for concatenated DH outputs
    size_t totalSize = 0;
    for (const auto& output : dhOutputs) {
        totalSize += output.size();
    }
    
    // Create a secure buffer for the concatenated values
    SecureVector concatenatedDH(totalSize);
    
    // Concatenate all DH outputs
    size_t offset = 0;
    for (const auto& output : dhOutputs) {
        // Use data() and direct memory copying instead of iterators to avoid const issues
        std::memcpy(concatenatedDH.data() + offset, output.data(), output.size());
        offset += output.size();
    }
    
    // Apply HKDF to derive the shared secret
    try {
        // X3DH uses HKDF with specific parameters
        static const QByteArray info = "404App-X3DH"; // Application-specific info
        
        // Before HKDF, X3DH requires prepending F bytes for domain separation
        // F is 32 bytes of 0xFF for X25519
        constexpr size_t F_BYTES = 32;
        constexpr size_t OUTPUT_BYTES = 32;
        
        // Prepare the input keying material: F || KM
        size_t ikm_len = F_BYTES + concatenatedDH.size();
        SecureVector ikm(ikm_len);
        
        // Fill first 32 bytes with 0xFF (this is F)
        std::memset(ikm.data(), 0xFF, F_BYTES);
        
        // Copy the concatenated DH outputs (this is KM)
        std::memcpy(ikm.data() + F_BYTES, concatenatedDH.data(), concatenatedDH.size());
        
        // Create zero-filled salt (length equal to hash output length)
        auto salt = make_secure_buffer<crypto_auth_hmacsha256_KEYBYTES>();
        std::memset(salt.get(), 0, crypto_auth_hmacsha256_KEYBYTES);
        
        // Manually implement HKDF using HMAC functions available in libsodium
        
        // Step 1: Extract - HMAC(salt, IKM) -> PRK
        auto prk = make_secure_buffer<crypto_auth_hmacsha256_BYTES>();
        crypto_auth_hmacsha256_state extract_state;
        crypto_auth_hmacsha256_init(&extract_state, salt.get(), crypto_auth_hmacsha256_KEYBYTES);
        crypto_auth_hmacsha256_update(&extract_state, ikm.data(), ikm_len);
        crypto_auth_hmacsha256_final(&extract_state, prk.get());
        
        // Step 2: Expand - HMAC(PRK, info || 0x01) -> OKM
        SecureVector output(OUTPUT_BYTES);
        
        crypto_auth_hmacsha256_state expand_state;
        crypto_auth_hmacsha256_init(&expand_state, prk.get(), crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_update(&expand_state, 
            reinterpret_cast<const unsigned char*>(info.constData()), 
            info.size());
        
        // Append counter byte (0x01)
        unsigned char counter = 0x01;
        crypto_auth_hmacsha256_update(&expand_state, &counter, 1);
        
        // Compute the HMAC
        auto hmac_output = make_secure_buffer<crypto_auth_hmacsha256_BYTES>();
        crypto_auth_hmacsha256_final(&expand_state, hmac_output.get());
        
        // Copy to output (truncate if necessary)
        std::memcpy(output.data(), hmac_output.get(), 
            std::min(static_cast<size_t>(OUTPUT_BYTES), 
                    static_cast<size_t>(crypto_auth_hmacsha256_BYTES)));
        
        return output;
    } catch (const std::exception& e) {
        qWarning() << "KDF operation failed:" << e.what();
        return SecureVector();
    }
}

/**
 * @brief Constructs the associated data for the X3DH protocol
 */
QByteArray SharedSecretUtils::constructAssociatedData(
    const QString& senderIdentityKeyBase64, 
    const QString& recipientIdentityKeyBase64) {
    
    QByteArray senderKey = QByteArray::fromBase64(senderIdentityKeyBase64.toUtf8());
    QByteArray recipientKey = QByteArray::fromBase64(recipientIdentityKeyBase64.toUtf8());
    
    // Use secure buffers for temporary storage of sensitive key data
    auto senderBuf = make_secure_buffer<crypto_sign_PUBLICKEYBYTES>();
    auto recipientBuf = make_secure_buffer<crypto_sign_PUBLICKEYBYTES>();
    
    // Only copy if the sizes are valid
    if (senderKey.size() <= crypto_sign_PUBLICKEYBYTES) {
        std::memcpy(senderBuf.get(), senderKey.constData(), senderKey.size());
    }
    
    if (recipientKey.size() <= crypto_sign_PUBLICKEYBYTES) {
        std::memcpy(recipientBuf.get(), recipientKey.constData(), recipientKey.size());
    }
    
    // Create the associated data
    QByteArray associatedData(senderKey.size() + recipientKey.size(), 0);
    std::memcpy(associatedData.data(), senderBuf.get(), senderKey.size());
    std::memcpy(associatedData.data() + senderKey.size(), recipientBuf.get(), recipientKey.size());
    
    return associatedData;
}

/**
 * @brief Converts Ed25519 keys to X25519 format for Diffie-Hellman operations
 *
 * Universal method that can convert public keys, private keys, or both.
 */
bool SharedSecretUtils::convertEd25519ToX25519Keys(
    const QString& publicKeyEd25519Base64,
    const QString& privateKeyEd25519Base64,
    QString& publicKeyX25519Base64,
    QString& privateKeyX25519Base64) {
    
    // Initialize output parameters as empty
    publicKeyX25519Base64.clear();
    privateKeyX25519Base64.clear();
    
    // Convert public key if provided
    if (!publicKeyEd25519Base64.isEmpty()) {
        QByteArray publicKeyEd25519 = QByteArray::fromBase64(publicKeyEd25519Base64.toUtf8());
        
        // Validate Ed25519 public key size
        if (publicKeyEd25519.size() != crypto_sign_PUBLICKEYBYTES) {
            qWarning() << "Invalid Ed25519 public key size";
            return false;
        }
        
        // Create buffer for X25519 public key
        auto publicKeyX25519 = make_secure_buffer<crypto_scalarmult_curve25519_BYTES>();
        
        // Convert Ed25519 public key to X25519
        if (crypto_sign_ed25519_pk_to_curve25519(
                publicKeyX25519.get(),
                reinterpret_cast<const unsigned char*>(publicKeyEd25519.constData())) != 0) {
            qWarning() << "Failed to convert Ed25519 public key to X25519";
            return false;
        }
        
        // Convert to base64 string
        publicKeyX25519Base64 = QByteArray(
            reinterpret_cast<char*>(publicKeyX25519.get()),
            crypto_scalarmult_curve25519_BYTES).toBase64();
    }
    
    // Convert private key if provided
    if (!privateKeyEd25519Base64.isEmpty()) {
        QByteArray privateKeyEd25519 = QByteArray::fromBase64(privateKeyEd25519Base64.toUtf8());
        
        // Validate Ed25519 private key size
        if (privateKeyEd25519.size() != crypto_sign_SECRETKEYBYTES) {
            qWarning() << "Invalid Ed25519 private key size";
            return false;
        }
        
        // Create buffer for X25519 private key
        auto privateKeyX25519 = make_secure_buffer<crypto_scalarmult_curve25519_SCALARBYTES>();
        
        // Convert Ed25519 private key to X25519
        if (crypto_sign_ed25519_sk_to_curve25519(
                privateKeyX25519.get(),
                reinterpret_cast<const unsigned char*>(privateKeyEd25519.constData())) != 0) {
            qWarning() << "Failed to convert Ed25519 private key to X25519";
            return false;
        }
        
        // Convert to base64 string
        privateKeyX25519Base64 = QByteArray(
            reinterpret_cast<char*>(privateKeyX25519.get()),
            crypto_scalarmult_curve25519_SCALARBYTES).toBase64();
    }
    
    // Successful if at least one conversion was performed
    return !publicKeyX25519Base64.isEmpty() || !privateKeyX25519Base64.isEmpty();
}

/**
 * @brief Generates a shared secret for the sender (Alice) according to X3DH protocol
 */
bool SharedSecretUtils::generateSenderSharedSecret(
    const QString& recipientUsername,
    const QString& recipientPublicKey,
    SecureVector& sharedSecret,
    QString& ephemeralPublicKey,
    bool& usedOneTimePrekey,
    QString& usedPreKeyId,
    QWidget* parent) {
    
    // 1. Retrieve recipient's key bundle
    QString recipientOneTimePrekey, recipientSignedPrekey;
    bool bundleRetrieved = X3DHNetworkUtils::getKeyBundleRequest(
        recipientUsername,
        recipientPublicKey,  // Ed25519 format for signature verification
        recipientOneTimePrekey,  // Will contain one-time prekey (OPKB) if available
        recipientSignedPrekey,   // Will contain signed prekey (SPKB)
        parent
    );
    
    if (!bundleRetrieved) {
        showErrorMessage(parent, "Bundle Error", 
                       "Failed to retrieve key bundle for " + recipientUsername);
        return false;
    }
    
    // Verify one-time prekey was retrieved (making it mandatory)
    if (recipientOneTimePrekey.isEmpty()) {
        showErrorMessage(parent, "Key Error", 
                       "One-time prekey is mandatory but was not retrieved from server for " + recipientUsername);
        return false;
    }
    
    // 2. Generate ephemeral key pair (EKA)
    QString ephemeralPrivateKey;
    bool keysGenerated = FileSharingUtils::generateEphemeralKeyPair(
        ephemeralPublicKey,    // Output: public key
        ephemeralPrivateKey    // Output: private key
    );
    
    if (!keysGenerated) {
        showErrorMessage(parent, "Key Error", "Failed to generate ephemeral key pair");
        return false;
    }
    
    // 3. Get sender's identity key (IKA)
    QString senderPublicKeyEd25519 = FriendStorageUtils::getUserPublicKey(
        LoginSessionManager::getInstance().getUsername(), parent);
    
    // Get private key from encrypted key storage
    QString senderPrivateKeyEd25519;
    if (!retrieveIdentityKeyMaterial(senderPrivateKeyEd25519, parent)) {
        showErrorMessage(parent, "Key Error", "Failed to retrieve identity key material");
        return false;
    }
    
    if (senderPublicKeyEd25519.isEmpty() || senderPrivateKeyEd25519.isEmpty()) {
        showErrorMessage(parent, "Key Error", "Failed to retrieve sender's identity keys");
        return false;
    }
    
    // 4. Convert Ed25519 identity keys to X25519 for DH operations
    QString senderPrivateKeyX25519, recipientPublicKeyX25519;
    if (!convertEd25519ToX25519Keys(
        recipientPublicKey,            // Recipient's Ed25519 public key
        senderPrivateKeyEd25519,       // Sender's Ed25519 private key
        recipientPublicKeyX25519,      // Output: Recipient's X25519 public key
        senderPrivateKeyX25519         // Output: Sender's X25519 private key
    )) {
        showErrorMessage(parent, "Conversion Error", "Failed to convert keys to X25519 format");
        return false;
    }
    
    // 5. Perform DH calculations according to X3DH protocol
    QVector<SecureVector> dhOutputs;
    
    // DH1 = DH(IKA_private, SPKB_public)
    // Sender's identity key with recipient's signed prekey
    SecureVector dh1 = performDH(senderPrivateKeyX25519, recipientSignedPrekey);
    if (dh1.empty()) {
        showErrorMessage(parent, "DH Error", "Key exchange calculation failed (DH1)");
        return false;
    }
    dhOutputs.append(dh1);
    
    // DH2 = DH(EKA_private, IKB_public)
    // Sender's ephemeral key with recipient's identity key
    SecureVector dh2 = performDH(ephemeralPrivateKey, recipientPublicKeyX25519);
    if (dh2.empty()) {
        showErrorMessage(parent, "DH Error", "Key exchange calculation failed (DH2)");
        return false;
    }
    dhOutputs.append(dh2);
    
    // DH3 = DH(EKA_private, SPKB_public)
    // Sender's ephemeral key with recipient's signed prekey
    SecureVector dh3 = performDH(ephemeralPrivateKey, recipientSignedPrekey);
    if (dh3.empty()) {
        showErrorMessage(parent, "DH Error", "Key exchange calculation failed (DH3)");
        return false;
    }
    dhOutputs.append(dh3);
    
    // One-time prekey is now mandatory, so we always perform DH4
    usedOneTimePrekey = true;
    usedPreKeyId = recipientOneTimePrekey;
    
    // DH4 = DH(EKA_private, OPKB_public)
    // Sender's ephemeral key with recipient's one-time prekey
    SecureVector dh4 = performDH(ephemeralPrivateKey, recipientOneTimePrekey);
    if (dh4.empty()) {
        showErrorMessage(parent, "DH Error", "Key exchange calculation failed (DH4)");
        return false;
    }
    dhOutputs.append(dh4);
    
    // 6. Apply KDF to derive the shared secret
    sharedSecret = applyKDF(dhOutputs);
    if (sharedSecret.empty()) {
        showErrorMessage(parent, "KDF Error", "Failed to derive shared secret");
        return false;
    }
    
    // 7. Clean up sensitive data (as per X3DH spec, the sender should delete ephemeral key)
    sodium_memzero(ephemeralPrivateKey.data(), ephemeralPrivateKey.size());
    sodium_memzero(senderPrivateKeyX25519.data(), senderPrivateKeyX25519.size());
    for (auto& output : dhOutputs) {
        sodium_memzero(output.data(), output.size());
    }
    
    qDebug() << "Successfully generated sender's shared secret with" << recipientUsername;
    
    return true;
}

/**
 * @brief Encrypts a file key using a shared secret
 */
bool SharedSecretUtils::encryptFileKeyWithSharedSecret(
    const SecureVector& sharedSecret,
    const QString& fileUuid,
    const QString& senderIdentityKey,
    const QString& recipientIdentityKey,
    QByteArray& encryptedKeyData,
    QWidget* parent) {
    
    // Validate inputs
    if (sharedSecret.empty() || fileUuid.isEmpty() || senderIdentityKey.isEmpty() || recipientIdentityKey.isEmpty()) {
        showErrorMessage(parent, "Encryption Error", "Invalid inputs for file key encryption");
        return false;
    }
    
    // Retrieve the file key by UUID
    auto fileKey = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    if (!FileCryptoUtils::getFileEncryptionKey(fileUuid, fileKey.get(), 
                                             crypto_aead_xchacha20poly1305_ietf_KEYBYTES, parent)) {
        showErrorMessage(parent, "Key Error", "Failed to retrieve file encryption key");
        return false;
    }
    
    // Create associated data using sender and recipient identity keys
    QByteArray associatedData = constructAssociatedData(senderIdentityKey, recipientIdentityKey);
    
    // Generate a nonce for encryption
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    EncryptionHelper encryptor;
    try {
        // Generate random nonce
        encryptor.generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        
        // Encrypt the file key using the shared secret as the key
        SecureVector encryptedFileKey = encryptor.encrypt(
            fileKey.get(),
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
            sharedSecret.data(),  // Use shared secret as encryption key
            nonce.get(),
            reinterpret_cast<const unsigned char*>(associatedData.constData()),
            associatedData.size()
        );
        
        // Prepare the output: nonce + encrypted file key
        encryptedKeyData.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + encryptedFileKey.size());
        
        // Copy nonce at the beginning
        std::memcpy(encryptedKeyData.data(), 
                   nonce.get(), 
                   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        
        // Copy encrypted file key after the nonce
        std::memcpy(encryptedKeyData.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                   encryptedFileKey.data(),
                   encryptedFileKey.size());
        
        qDebug() << "File key encrypted successfully";
        return true;
        
    } catch (const std::exception& e) {
        showErrorMessage(parent, "Encryption Error", 
                      QString("Failed to encrypt file key: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Decrypts a file key using a shared secret
 */
bool SharedSecretUtils::decryptFileKeyWithSharedSecret(
    const SecureVector& sharedSecret,
    const QByteArray& encryptedKeyData,
    const QString& senderIdentityKey,
    const QString& recipientIdentityKey,
    unsigned char* fileKey,
    size_t fileKeySize,
    QWidget* parent) {
    
    // Validate inputs
    if (sharedSecret.empty() || encryptedKeyData.isEmpty() || 
        senderIdentityKey.isEmpty() || recipientIdentityKey.isEmpty() ||
        fileKey == nullptr || fileKeySize < crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        showErrorMessage(parent, "Decryption Error", "Invalid inputs for file key decryption");
        return false;
    }
    
    // Verify encrypted data has enough bytes for nonce + ciphertext
    if (encryptedKeyData.size() <= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        showErrorMessage(parent, "Decryption Error", "Encrypted key data is too small");
        return false;
    }
    
    // Create associated data using sender and recipient identity keys
    QByteArray associatedData = constructAssociatedData(senderIdentityKey, recipientIdentityKey);
    
    try {
        // Extract nonce from the beginning of encrypted data
        auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
        std::memcpy(nonce.get(), encryptedKeyData.constData(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        
        // Extract ciphertext (encrypted file key)
        const unsigned char* ciphertext = 
            reinterpret_cast<const unsigned char*>(encryptedKeyData.constData()) + 
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        
        const unsigned long long ciphertext_len = 
            encryptedKeyData.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        
        // Decrypt the file key using the shared secret
        EncryptionHelper decryptor;
        SecureVector decryptedFileKey = decryptor.decrypt(
            ciphertext,
            ciphertext_len,
            sharedSecret.data(),  // Use shared secret as decryption key
            nonce.get(),
            reinterpret_cast<const unsigned char*>(associatedData.constData()),
            associatedData.size()
        );
        
        // Ensure the decrypted key has the expected size
        if (decryptedFileKey.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
            showErrorMessage(parent, "Decryption Error", "Decrypted file key has incorrect size");
            return false;
        }
        
        // Copy the decrypted key to the output buffer
        std::memcpy(fileKey, decryptedFileKey.data(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        
        qDebug() << "File key decrypted successfully";
        return true;
        
    } catch (const std::exception& e) {
        showErrorMessage(parent, "Decryption Error", 
                      QString("Failed to decrypt file key: %1").arg(e.what()));
        return false;
    }
}

/**
 * @brief Retrieves identity key material from encrypted key storage
 */
bool SharedSecretUtils::retrieveIdentityKeyMaterial(QString& privateKey, QWidget* parent) {
    // Use FileSharingUtils public methods instead of private ones
    QByteArray jsonData;
    if (!FileSharingUtils::getDecryptedKeyStorage(jsonData)) {
        showErrorMessage(parent, "Storage Error", "Failed to retrieve and decrypt key storage");
        return false;
    }
    
    // Parse JSON data
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        showErrorMessage(parent, "Parse Error", 
                       "Failed to parse key storage JSON: " + parseError.errorString());
        return false;
    }
    
    QJsonObject rootObject = doc.object();
    
    // Extract the private key
    if (rootObject.contains("privateKey") && rootObject["privateKey"].isString()) {
        privateKey = rootObject["privateKey"].toString();
        qDebug() << "Successfully retrieved identity private key";
        return true;
    } else {
        showErrorMessage(parent, "Key Error", "Identity private key not found in key storage");
        return false;
    }
}
