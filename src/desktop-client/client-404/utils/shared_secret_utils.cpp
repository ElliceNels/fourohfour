#include "shared_secret_utils.h"
#include <QDebug>
#include <sodium.h>
#include <QByteArray>
#include "utils/file_sharing_utils.h"
#include "crypto/encryptionhelper.h"
#include "utils/securebufferutils.h"

/**
 * @brief Generates a shared secret key for the recipient according to X3DH protocol
 *
 * This implementation follows a modified X3DH protocol specification where one-time
 * prekeys are mandatory for additional security:
 * 1. Retrieve all necessary private keys 
 * 2. Perform multiple DH operations including the mandatory DH4 with one-time prekey
 * 3. Concatenate DH outputs and apply KDF 
 * 4. Delete one-time prekey if specified
 *
 * Note: Identity keys are in Ed25519 format and are converted to X25519 before DH operations
 *
 * @param senderIdentityKeyBase64 Base64-encoded sender's identity key (Ed25519 format)
 * @param senderEphemeralKeyBase64 Base64-encoded sender's ephemeral key (X25519 format)
 * @param recipientSignedPreKeyBase64 Base64-encoded recipient's signed prekey (X25519 format)
 * @param oneTimePreKeyBase64 Base64-encoded one-time prekey (X25519 format) - mandatory
 * @param removeUsedOneTimePreKey Whether to delete the one-time prekey after use
 * @return SecureVector The derived shared secret key, empty if the operation failed
 */
SecureVector SharedSecretUtils::generateRecipientSharedSecret(
    const QString& senderIdentityKeyBase64,
    const QString& senderEphemeralKeyBase64, 
    const QString& recipientSignedPreKeyBase64,
    const QString& oneTimePreKeyBase64,
    bool removeUsedOneTimePreKey) {
    
    // Validate inputs
    if (senderIdentityKeyBase64.isEmpty() || senderEphemeralKeyBase64.isEmpty() || 
        recipientSignedPreKeyBase64.isEmpty() || oneTimePreKeyBase64.isEmpty()) {
        qWarning() << "Required keys missing for shared secret generation";
        return SecureVector();
    }
    
    // Retrieve recipient's private keys using existing FileSharingUtils method
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
        qWarning() << "Failed to retrieve recipient's private keys for shared secret generation";
        return SecureVector();
    }
    
    // Verify one-time prekey was retrieved (mandatory in our implementation)
    if (privateOneTimePreKey.isEmpty()) {
        qWarning() << "One-time prekey is mandatory but was not retrieved successfully";
        return SecureVector();
    }
    
    // Convert Ed25519 keys to X25519 for Diffie-Hellman operations
    QString senderIdentityKeyX25519Base64;
    QString recipientIdentityKeyX25519Base64;
    
    if (!convertEd25519ToX25519Keys(senderIdentityKeyBase64, privateIdentityKey,
                                    senderIdentityKeyX25519Base64, recipientIdentityKeyX25519Base64)) {
        qWarning() << "Failed to convert Ed25519 identity keys to X25519";
        return SecureVector();
    }
    
    // Calculate DH outputs according to X3DH protocol
    QVector<SecureVector> dhOutputs;
    
    // DH1 = DH(SPKB_private, IKA_public)
    // Bob uses his signed prekey private key with Alice's identity public key
    SecureVector dh1 = performDH(privateSignedPreKey, senderIdentityKeyX25519Base64);
    if (dh1.empty()) {
        qWarning() << "DH1 calculation failed";
        return SecureVector();
    }
    dhOutputs.append(dh1);
    
    // DH2 = DH(IKB_private, EKA_public)
    // Bob uses his identity private key with Alice's ephemeral public key
    SecureVector dh2 = performDH(recipientIdentityKeyX25519Base64, senderEphemeralKeyBase64);
    if (dh2.empty()) {
        qWarning() << "DH2 calculation failed";
        return SecureVector();
    }
    dhOutputs.append(dh2);
    
    // DH3 = DH(SPKB_private, EKA_public)
    // Bob uses his signed prekey private key with Alice's ephemeral public key
    SecureVector dh3 = performDH(privateSignedPreKey, senderEphemeralKeyBase64);
    if (dh3.empty()) {
        qWarning() << "DH3 calculation failed";
        return SecureVector();
    }
    dhOutputs.append(dh3);
    
    // DH4 = DH(OPKB_private, EKA_public)
    // Bob uses his one-time prekey private key with Alice's ephemeral public key
    SecureVector dh4 = performDH(privateOneTimePreKey, senderEphemeralKeyBase64);
    if (dh4.empty()) {
        qWarning() << "DH4 calculation failed";
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
 *
 * @param privateKeyBase64 Base64-encoded private key
 * @param publicKeyBase64 Base64-encoded public key
 * @return SecureVector The DH shared secret, empty if operation failed
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
 *
 * This implementation follows the X3DH specification for KDF:
 * SK = KDF(DH1 || DH2 || DH3 [|| DH4])
 * 
 * Uses HKDF as specified in section 2.2 of the X3DH protocol
 *
 * @param dhOutputs Vector of DH outputs to concatenate as input
 * @return SecureVector The derived key, empty if operation failed
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
        auto salt = make_secure_buffer<crypto_hash_sha256_BYTES>();
        std::memset(salt.get(), 0, crypto_hash_sha256_BYTES);
        
        // Extract phase - create the PRK (pseudorandom key) using secure buffer
        auto prk = make_secure_buffer<crypto_kdf_hkdf_sha256_KEYBYTES>();
        if (crypto_kdf_hkdf_sha256_extract(
                prk.get(), 
                salt.get(), crypto_hash_sha256_BYTES,
                ikm.data(), ikm_len) != 0) {
            qWarning() << "HKDF extract operation failed";
            return SecureVector();
        }
        
        // Expand phase - derive the output key material
        SecureVector output(OUTPUT_BYTES);
        if (crypto_kdf_hkdf_sha256_expand(
                output.data(), OUTPUT_BYTES,
                reinterpret_cast<const unsigned char*>(info.constData()), info.size(),
                prk.get()) != 0) {
            qWarning() << "HKDF expand operation failed";
            return SecureVector();
        }
        
        // No need to manually wipe prk - SodiumZeroDeleter will handle it
        return output;
    } catch (const std::exception& e) {
        qWarning() << "KDF operation failed:" << e.what();
        return SecureVector();
    }
}

/**
 * @brief Constructs the associated data for the X3DH protocol
 *
 * The associated data is used for message authentication and binding the
 * identities of the communicating parties to the encryption.
 *
 * @param senderIdentityKeyBase64 Base64-encoded sender's identity key
 * @param recipientIdentityKeyBase64 Base64-encoded recipient's identity key
 * @return QByteArray The associated data byte sequence
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
 * @brief Converts Ed25519 identity keys to X25519 format for Diffie-Hellman operations
 *
 * @param senderIdentityKeyEd25519Base64 Base64-encoded sender's Ed25519 identity public key
 * @param recipientIdentityKeyEd25519Base64 Base64-encoded recipient's Ed25519 identity private key
 * @param senderIdentityKeyX25519Base64 Output parameter for sender's converted X25519 public key
 * @param recipientIdentityKeyX25519Base64 Output parameter for recipient's converted X25519 private key
 * @return bool True if conversion successful, false otherwise
 */
bool SharedSecretUtils::convertEd25519ToX25519Keys(
    const QString& senderIdentityKeyEd25519Base64,
    const QString& recipientIdentityKeyEd25519Base64,
    QString& senderIdentityKeyX25519Base64,
    QString& recipientIdentityKeyX25519Base64) {
    
    // Decode base64 keys
    QByteArray senderPkEd25519 = QByteArray::fromBase64(senderIdentityKeyEd25519Base64.toUtf8());
    QByteArray recipientSkEd25519 = QByteArray::fromBase64(recipientIdentityKeyEd25519Base64.toUtf8());
    
    // Validate Ed25519 key sizes
    if (senderPkEd25519.size() != crypto_sign_PUBLICKEYBYTES ||
        recipientSkEd25519.size() != crypto_sign_SECRETKEYBYTES) {
        qWarning() << "Invalid Ed25519 key size";
        return false;
    }
    
    // Create buffers for X25519 keys
    auto senderPkX25519 = make_secure_buffer<crypto_scalarmult_curve25519_BYTES>();
    auto recipientSkX25519 = make_secure_buffer<crypto_scalarmult_curve25519_SCALARBYTES>();
    
    // Convert sender's Ed25519 public key to X25519
    if (crypto_sign_ed25519_pk_to_curve25519(
            senderPkX25519.get(),
            reinterpret_cast<const unsigned char*>(senderPkEd25519.constData())) != 0) {
        qWarning() << "Failed to convert sender's Ed25519 public key to X25519";
        return false;
    }
    
    // Convert recipient's Ed25519 private key to X25519
    if (crypto_sign_ed25519_sk_to_curve25519(
            recipientSkX25519.get(),
            reinterpret_cast<const unsigned char*>(recipientSkEd25519.constData())) != 0) {
        qWarning() << "Failed to convert recipient's Ed25519 private key to X25519";
        return false;
    }
    
    // Convert to base64 strings
    senderIdentityKeyX25519Base64 = QByteArray(
        reinterpret_cast<char*>(senderPkX25519.get()),
        crypto_scalarmult_curve25519_BYTES).toBase64();
    
    recipientIdentityKeyX25519Base64 = QByteArray(
        reinterpret_cast<char*>(recipientSkX25519.get()),
        crypto_scalarmult_curve25519_SCALARBYTES).toBase64();
    
    return true;
}
