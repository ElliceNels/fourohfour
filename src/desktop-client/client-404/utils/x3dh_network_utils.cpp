#include "x3dh_network_utils.h"
#include <QDebug>
#include <QMessageBox>
#include <QDateTime>
#include <QJsonObject>
#include "core/loginsessionmanager.h"
#include "constants.h"
#include "utils/file_sharing_utils.h"

/**
 * @brief Retrieves a key bundle from the server for a specific user
 */
bool X3DHNetworkUtils::getKeyBundleRequest(
    const QString& username,
    const QString& userPublicKey,
    QString& otpk,
    QString& spk,
    QWidget* parent) {
    
    // Validate input parameters
    if (!validateKeyBundleInputs(username, parent)) {
        return false;
    }
    
    // Make the request to the server
    RequestUtils::Response response = requestKeyBundle(username);
    
    if (!response.success || response.jsonData.isEmpty()) {
        qWarning() << "Failed to retrieve key bundle:" 
                  << QString::fromStdString(response.errorMessage);
        if (parent) {
            QMessageBox::warning(parent, "Error", 
                                "Failed to retrieve key bundle for " + username);
        }
        return false;
    }
    
    // Extract the required fields from the response
    QString retrievedOTPK, retrievedSPK, signature, updatedAtStr;
    if (!extractKeyBundleFields(response, retrievedOTPK, retrievedSPK, signature, updatedAtStr, parent)) {
        return false;
    }
    
    // Check if the key is expired
    if (!isSignedPrekeyValid(updatedAtStr, username, parent)) {
        return false;
    }
    
    // Verify the signature
    if (!FileSharingUtils::verifySignedPreKey(userPublicKey, retrievedSPK, signature)) {
        qWarning() << "Failed to verify signature for" << username << "signed prekey";
        if (parent) {
            QMessageBox::warning(parent, "Invalid Signature",
                                "The signature verification failed for " + username + "'s signed prekey.");
        }
        return false;
    }
    
    // Everything is valid, set output parameters
    otpk = retrievedOTPK;
    spk = retrievedSPK;
    
    // Log success details
    logKeyBundleSuccess(username, otpk, spk);
    
    return true;
}

/**
 * @brief Validates inputs for key bundle retrieval
 */
bool X3DHNetworkUtils::validateKeyBundleInputs(const QString& username, QWidget* parent) {
    if (username.isEmpty()) {
        qWarning() << "Cannot retrieve key bundle for empty username";
        if (parent) {
            QMessageBox::warning(parent, "Error", "Username cannot be empty");
        }
        return false;
    }
    return true;
}

/**
 * @brief Makes a request to retrieve a key bundle from the server
 */
RequestUtils::Response X3DHNetworkUtils::requestKeyBundle(const QString& username) {
    // Construct the query parameters
    QJsonObject params;
    params["username"] = username;
    
    // Make the request to the server
    return LoginSessionManager::getInstance().get(RETRIEVE_KEY_BUNDLE_ENDPOINT, params);
}

/**
 * @brief Extracts required fields from the key bundle response
 */
bool X3DHNetworkUtils::extractKeyBundleFields(
    const RequestUtils::Response& response,
    QString& otpk, 
    QString& spk, 
    QString& signature, 
    QString& updatedAtStr,
    QWidget* parent) {
    
    QJsonObject jsonObj = response.jsonData.object();
    
    // Check if all required fields exist
    if (!jsonObj.contains("otpk") || !jsonObj.contains("spk") || 
        !jsonObj.contains("spk_signature") || !jsonObj.contains("updatedAt")) {
        qWarning() << "Key bundle missing required fields";
        if (parent) {
            QMessageBox::warning(parent, "Error", 
                               "Retrieved key bundle is incomplete");
        }
        return false;
    }
    
    // Extract values from the response
    otpk = jsonObj["otpk"].toString();
    spk = jsonObj["spk"].toString();
    signature = jsonObj["spk_signature"].toString();
    updatedAtStr = jsonObj["updatedAt"].toString();
    
    return true;
}

/**
 * @brief Checks if a signed prekey has expired
 */
bool X3DHNetworkUtils::isSignedPrekeyValid(
    const QString& updatedAtStr, 
    const QString& username, 
    QWidget* parent) {
    
    QDateTime updatedAt = QDateTime::fromString(updatedAtStr, Qt::ISODate);
    if (!updatedAt.isValid()) {
        qWarning() << "Invalid updatedAt timestamp for user" << username << ":" << updatedAtStr;
        if (parent) {
            QMessageBox::warning(parent, "Error",
                               "The timestamp for the signed key of " + username +
                               " is invalid. Please try again later.");
        }
        return false;
    }
    
    QDateTime currentDate = QDateTime::currentDateTime();
    int daysSinceUpdate = updatedAt.daysTo(currentDate);
    
    if (daysSinceUpdate > MAX_AGE_DAYS) {
        qWarning() << "Signed prekey for" << username << "is" << daysSinceUpdate << "days old (max:" << MAX_AGE_DAYS << "days)";
        if (parent) {
            QMessageBox::warning(parent, "Expired Key",
                                "Cannot send message as the signed key of " + username + 
                                " is expired (" + QString::number(daysSinceUpdate) + " days old).");
        }
        return false;
    }
    
    return true;
}

/**
 * @brief Display debug information about the retrieved key bundle
 */
void X3DHNetworkUtils::logKeyBundleSuccess(
    const QString& username, 
    const QString& otpk, 
    const QString& spk) {
    
    qDebug() << "Successfully retrieved and verified key bundle for" << username
             << "- OTPK:" << otpk.left(8) + "..." // Only show first few chars for security
             << "- SPK:" << spk.left(8) + "...";  // Only show first few chars for security
}
