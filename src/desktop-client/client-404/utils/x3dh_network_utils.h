#ifndef X3DH_NETWORK_UTILS_H
#define X3DH_NETWORK_UTILS_H

#include <QString>
#include <QJsonObject>
#include <QDateTime>
#include <QMessageBox>
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
