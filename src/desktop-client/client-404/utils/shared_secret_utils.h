#ifndef SHARED_SECRET_UTILS_H
#define SHARED_SECRET_UTILS_H

#include <QByteArray>
#include <QString>
#include <QVector>
#include <QWidget>
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
     * @param parent Optional parent widget for displaying error messages
     * @return SecureVector The derived shared secret key, empty if the operation failed
     */
    static SecureVector generateRecipientSharedSecret(
        const QString& senderIdentityKeyBase64,
        const QString& senderEphemeralKeyBase64,
        const QString& recipientSignedPreKeyBase64,
        const QString& oneTimePreKeyBase64,
        bool removeUsedOneTimePreKey = true,
        QWidget* parent = nullptr);

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

    /**
     * @brief Generates a shared secret key for the sender (Alice) according to X3DH protocol
     *
     * This method implements section 3.3 of the X3DH protocol specification.
     * It retrieves the recipient's key bundle, generates an ephemeral key pair,
     * performs the necessary DH calculations, and derives the shared secret.
     *
     * @param recipientUsername The username of the recipient (Bob)
     * @param recipientPublicKey The identity public key of the recipient for verification
     * @param sharedSecret Output parameter that will contain the generated shared secret
     * @param ephemeralPublicKey Output parameter for the ephemeral public key to send to recipient
     * @param usedOneTimePrekey Output parameter indicating if a one-time prekey was used
     * @param usedPreKeyId Output parameter for the ID of the used prekey (if applicable)
     * @param parent Optional parent widget for displaying message boxes
     * @return bool True if the shared secret was successfully generated
     */
    static bool generateSenderSharedSecret(
        const QString& recipientUsername,
        const QString& recipientPublicKey,
        SecureVector& sharedSecret,
        QString& ephemeralPublicKey,
        bool& usedOneTimePrekey,
        QString& usedPreKeyId,
        QWidget* parent = nullptr);

private:
    /**
     * @brief Converts Ed25519 keys to X25519 format for Diffie-Hellman operations
     *
     * Generic method that handles both sender and recipient key conversions.
     *
     * @param publicKeyEd25519Base64 Base64-encoded Ed25519 public key
     * @param privateKeyEd25519Base64 Base64-encoded Ed25519 private key (can be empty for public-only conversion)
     * @param publicKeyX25519Base64 Output parameter for converted X25519 public key (if input public key provided)
     * @param privateKeyX25519Base64 Output parameter for converted X25519 private key (if input private key provided)
     * @return bool True if conversion successful, false otherwise
     */
    static bool convertEd25519ToX25519Keys(
        const QString& publicKeyEd25519Base64,
        const QString& privateKeyEd25519Base64,
        QString& publicKeyX25519Base64,
        QString& privateKeyX25519Base64);

    /**
     * @brief Performs a Diffie-Hellman key exchange using X25519
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

    /**
     * @brief Retrieves identity key material from encrypted key storage
     *
     * @param privateKey Output parameter for the retrieved private key
     * @param parent Optional parent widget for displaying error messages
     * @return bool True if the key was successfully retrieved, false otherwise
     */
    static bool retrieveIdentityKeyMaterial(QString& privateKey, QWidget* parent);
    
    /**
     * @brief Shows an error message if parent widget is available
     *
     * @param parent Widget to show the error on, can be nullptr
     * @param title Error title
     * @param message Error message
     */
    static void showErrorMessage(QWidget* parent, const QString& title, const QString& message);
};

#endif // SHARED_SECRET_UTILS_H
