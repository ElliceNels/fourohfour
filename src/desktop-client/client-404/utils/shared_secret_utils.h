#ifndef SHARED_SECRET_UTILS_H
#define SHARED_SECRET_UTILS_H

#include <QByteArray>
#include <QString>
#include <QVector>
#include "utils/securevector.h"

class SharedSecretUtils {
public:
    /**
     * @brief Generates a shared secret key for the recipient according to X3DH protocol
     *
     * @param senderIdentityKeyBase64 Base64-encoded sender's identity key (Ed25519 format)
     * @param senderEphemeralKeyBase64 Base64-encoded sender's ephemeral key (X25519 format)
     * @param recipientSignedPreKeyBase64 Base64-encoded recipient's signed prekey (X25519 format)
     * @param oneTimePreKeyBase64 Base64-encoded one-time prekey (X25519 format) - mandatory
     * @param removeUsedOneTimePreKey Whether to delete the one-time prekey after use
     * @return SecureVector The derived shared secret key, empty if the operation failed
     */
    static SecureVector generateRecipientSharedSecret(
        const QString& senderIdentityKeyBase64,
        const QString& senderEphemeralKeyBase64,
        const QString& recipientSignedPreKeyBase64,
        const QString& oneTimePreKeyBase64,
        bool removeUsedOneTimePreKey = true);

    /**
     * @brief Constructs the associated data for the X3DH protocol
     *
     * @param senderIdentityKeyBase64 Base64-encoded sender's identity key
     * @param recipientIdentityKeyBase64 Base64-encoded recipient's identity key
     * @return QByteArray The associated data byte sequence
     */
    static QByteArray constructAssociatedData(
        const QString& senderIdentityKeyBase64,
        const QString& recipientIdentityKeyBase64);

private:
    /**
     * @brief Converts Ed25519 identity keys to X25519 format for Diffie-Hellman operations
     *
     * @param senderIdentityKeyEd25519Base64 Base64-encoded sender's Ed25519 identity public key
     * @param recipientIdentityKeyEd25519Base64 Base64-encoded recipient's Ed25519 identity private key
     * @param senderIdentityKeyX25519Base64 Output parameter for sender's converted X25519 public key
     * @param recipientIdentityKeyX25519Base64 Output parameter for recipient's converted X25519 private key
     * @return bool True if conversion successful, false otherwise
     */
    static bool convertEd25519ToX25519Keys(
        const QString& senderIdentityKeyEd25519Base64,
        const QString& recipientIdentityKeyEd25519Base64,
        QString& senderIdentityKeyX25519Base64,
        QString& recipientIdentityKeyX25519Base64);

    /**
     * @brief Performs a Diffie-Hellman key exchange
     *
     * @param privateKeyBase64 Base64-encoded private key (X25519 format)
     * @param publicKeyBase64 Base64-encoded public key (X25519 format)
     * @return SecureVector The DH shared secret, empty if operation failed
     */
    static SecureVector performDH(
        const QString& privateKeyBase64,
        const QString& publicKeyBase64);

    /**
     * @brief Applies the KDF to derive a shared secret key
     *
     * @param dhOutputs Vector of DH outputs to concatenate as input
     * @return SecureVector The derived key, empty if operation failed
     */
    static SecureVector applyKDF(const QVector<SecureVector>& dhOutputs);
};

#endif // SHARED_SECRET_UTILS_H
