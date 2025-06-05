#ifndef FILE_SHARING_MANAGER_UTILS_H
#define FILE_SHARING_MANAGER_UTILS_H

#include <QString>
#include <QWidget>
#include <QByteArray>
#include "utils/securevector.h"  // Add this include for SecureVector

/**
 * @brief Manages the complete file sharing workflow through X3DH protocol
 * 
 * This class provides high-level methods that combine various lower-level utilities
 * to manage the complete workflow of sharing files securely with other users.
 */
class FileSharingManagerUtils {
public:
    /**
     * @brief Shares a file with another user using X3DH protocol
     * 
     * This method combines all the steps required to share a file with another user:
     * 1. Generates a shared secret using X3DH protocol
     * 2. Retrieves and encrypts the file key with the shared secret
     * 3. Creates a permission on the server for the recipient
     *
     * @param fileUuid UUID of the file to share
     * @param recipientUsername Username of the recipient
     * @param recipientPublicKey Recipient's public key for X3DH protocol
     * @param parent Optional parent widget for displaying UI feedback
     * @return bool True if the file was successfully shared
     */
    static bool shareFileWithUser(
        const QString& fileUuid,
        const QString& recipientUsername,
        const QString& recipientPublicKey,
        QWidget* parent = nullptr);

    /**
     * @brief Gets the decrypted file key for a shared file
     * 
     * This method handles the recipient side of key exchange:
     * 1. Generates shared secret using X3DH protocol
     * 2. Decrypts the file encryption key using the shared secret
     * 3. Returns the decrypted key for file decryption
     *
     * @param fileUuid UUID of the file
     * @param senderIdentityKey Sender's identity key (public key)
     * @param senderEphemeralKey Sender's ephemeral key for this sharing
     * @param encryptedKeyData Encrypted file key data
     * @param recipientSignedPreKey Recipient's signed prekey used in this sharing
     * @param oneTimePreKey One-time prekey used in this sharing
     * @param fileKey Output buffer to receive the decrypted file key
     * @param fileKeySize Size of the output buffer
     * @param parent Optional parent widget for displaying UI feedback
     * @return bool True if the file key was successfully decrypted
     */
    static bool receiveSharedFile(
        const QString& fileUuid,
        const QString& senderIdentityKey,
        const QString& senderEphemeralKey,
        const QByteArray& encryptedKeyData,
        const QString& recipientSignedPreKey,
        const QString& oneTimePreKey,
        unsigned char* fileKey,
        size_t fileKeySize,
        QWidget* parent = nullptr);

private:
    /**
     * @brief Shows a progress message to the user if a parent widget is available
     * 
     * @param parent The parent widget
     * @param message The message to display
     */
    static void showProgressMessage(QWidget* parent, const QString& message);
    
    /**
     * @brief Shows an error message to the user
     * 
     * @param parent The parent widget for displaying error messages
     * @param title The error title
     * @param message The error message
     */
    static void showErrorMessage(QWidget* parent, const QString& title, const QString& message);
};

#endif // FILE_SHARING_MANAGER_UTILS_H
