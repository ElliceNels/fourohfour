#ifndef X3DH_NETWORK_UTILS_H
#define X3DH_NETWORK_UTILS_H

#include <QString>
#include <QJsonObject>
#include <QDateTime>
#include <QMessageBox>
#include <QJsonArray>
#include "utils/request_utils.h"

/**
 * @brief Utility class for X3DH network operations
 * 
 * This class handles network operations specific to the Extended Triple Diffie-Hellman 
 * (X3DH) key agreement protocol, such as fetching prekey bundles and uploading prekeys.
 */
class X3DHNetworkUtils {
public:
    /**
     * @brief Retrieves a key bundle from the server for a specific user
     * 
     * This method fetches the one-time prekey, signed prekey, and signature
     * for the specified username. It validates the key age and signature.
     *
     * @param username The username to get the key bundle for
     * @param userPublicKey The public key of the user for signature verification
     * @param otpk Reference to store the one-time prekey
     * @param spk Reference to store the signed prekey
     * @param parent Optional parent widget for displaying message boxes
     * @return bool True if the key bundle was successfully retrieved and validated
     */
    static bool getKeyBundleRequest(
        const QString& username,
        const QString& userPublicKey,
        QString& otpk,
        QString& spk,
        QWidget* parent = nullptr);
        
    /**
     * @brief Creates a permission for a file to be accessed by a recipient
     * 
     * This method creates a permission on the server that allows the specified
     * recipient to access a shared file. It sends the encrypted file key that was
     * encrypted with the shared secret from the X3DH protocol.
     *
     * @param fileUuid UUID of the file being shared
     * @param recipientUsername Username of the user receiving permission
     * @param encryptedKey The file key encrypted with the shared secret
     * @param oneTimePreKey The one-time prekey used in the X3DH protocol
     * @param ephemeralKey The ephemeral key used in the X3DH protocol
     * @param parent Optional parent widget for displaying message boxes
     * @return bool True if the permission was successfully created
     */
    static bool createPermission(
        const QString& fileUuid,
        const QString& recipientUsername,
        const QByteArray& encryptedKey,
        const QString& oneTimePreKey,
        const QString& ephemeralKey,
        QWidget* parent = nullptr);

    /**
     * @brief Gets the list of users who have access to a specific file
     * 
     * @param fileUuid UUID of the file
     * @param parent Optional parent widget for displaying messages
     * @return QStringList List of usernames with access to the file
     */
    static QStringList getFilePermissions(
        const QString& fileUuid,
        QWidget* parent = nullptr);
        
    /**
     * @brief Removes a permission for a user to access a file
     * 
     * @param fileUuid UUID of the file
     * @param username Username of the user whose permission should be removed
     * @param parent Optional parent widget for displaying message boxes
     * @return bool True if the permission was successfully removed
     */
    static bool removePermission(
        const QString& fileUuid,
        const QString& username,
        QWidget* parent = nullptr);

    /**
     * @brief Sends one-time pre-keys to the server for secure communication
     * 
     * This method sends the JSON array of base64-encoded one-time pre-keys
     * to the server's /add_otpks endpoint. On success, it logs the 
     * number of OTPKs stored on the server.
     *
     * @param oneTimePreKeysJson JSON array of base64-encoded one-time pre-key public keys
     * @param parent Optional parent widget for displaying message boxes
     * @return bool True if the keys were successfully sent and stored, false otherwise
     */
    static bool uploadOneTimePreKeys(const QJsonArray& oneTimePreKeysJson, QWidget* parent = nullptr);

    /**
     * @brief Uploads a new signed pre-key and its signature to the server
     * 
     * This method sends a new signed pre-key pair and its signature to the server
     * to replace the current one. This should be done periodically for security
     * as recommended by the X3DH protocol.
     *
     * @param signedPreKeyPublic The base64-encoded public part of the signed pre-key
     * @param signature The base64-encoded signature of the signed pre-key
     * @param parent Optional parent widget for displaying error messages
     * @return bool True if the update was successful, false otherwise
     */
    static bool updateSignedPreKey(
        const QString& signedPreKeyPublic,
        const QString& signature,
        QWidget* parent = nullptr);

private:
    /**
     * @brief Validates inputs for key bundle retrieval
     * 
     * @param username The username to validate
     * @param parent The parent widget for displaying error messages
     * @return bool True if the inputs are valid, false otherwise
     */
    static bool validateKeyBundleInputs(const QString& username, QWidget* parent);
    
    /**
     * @brief Makes a request to retrieve a key bundle from the server
     * 
     * @param username The username to retrieve the key bundle for
     * @return RequestUtils::Response The server response
     */
    static RequestUtils::Response requestKeyBundle(const QString& username);
    
    /**
     * @brief Extracts required fields from the key bundle response
     * 
     * @param response The server response
     * @param otpk Reference to store the one-time prekey
     * @param spk Reference to store the signed prekey
     * @param signature Reference to store the signature
     * @param updatedAtStr Reference to store the updated timestamp
     * @param parent The parent widget for displaying error messages
     * @return bool True if all required fields were extracted, false otherwise
     */
    static bool extractKeyBundleFields(
        const RequestUtils::Response& response,
        QString& otpk, 
        QString& spk, 
        QString& signature, 
        QString& updatedAtStr,
        QWidget* parent);
    
    /**
     * @brief Checks if a signed prekey has expired
     * 
     * @param updatedAtStr The timestamp when the key was last updated
     * @param username The username associated with the key
     * @param parent The parent widget for displaying error messages
     * @return bool True if the key is still valid, false if expired
     */
    static bool isSignedPrekeyValid(
        const QString& updatedAtStr, 
        const QString& username, 
        QWidget* parent);
    
    /**
     * @brief Display debug information about the retrieved key bundle
     * 
     * @param username The username the key bundle belongs to
     * @param otpk The one-time prekey
     * @param spk The signed prekey
     */
    static void logKeyBundleSuccess(
        const QString& username, 
        const QString& otpk, 
        const QString& spk);
};

#endif // X3DH_NETWORK_UTILS_H
