#include "x3dh_network_utils.h"
#include <QDebug>
#include <QMessageBox>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
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

/**
 * @brief Creates a permission for a file to be accessed by a recipient
 */
bool X3DHNetworkUtils::createPermission(
    const QString& fileUuid,
    const QString& recipientUsername,
    const QByteArray& encryptedKey,
    const QString& oneTimePreKey,
    const QString& ephemeralKey,
    QWidget* parent) {
    
    // Validate inputs
    if (fileUuid.isEmpty() || recipientUsername.isEmpty() || encryptedKey.isEmpty() ||
        oneTimePreKey.isEmpty() || ephemeralKey.isEmpty()) {
        if (parent) {
            QMessageBox::warning(parent, "Invalid Input", 
                                "All fields are required for creating a file permission.");
        }
        qWarning() << "Invalid input for file permission creation";
        return false;
    }
    
    // Prepare request data
    QJsonObject requestData;
    requestData["file_uuid"] = fileUuid;
    requestData["username"] = recipientUsername;
    requestData["key_for_recipient"] = QString(encryptedKey.toBase64());
    requestData["otpk"] = oneTimePreKey;
    requestData["ephemeral_key"] = ephemeralKey;
    
    // Make the API request to create permission using LoginSessionManager
    RequestUtils::Response response = LoginSessionManager::getInstance().post(CREATE_PERMISSION_ENDPOINT, requestData);
    
    // Check if request was successful
    if (!response.success) {
        QString errorMessage = "Failed to create file permission: " + QString::fromStdString(response.errorMessage);
        if (parent) {
            QMessageBox::warning(parent, "Permission Error", errorMessage);
        }
        qWarning() << errorMessage;
        return false;
    }
    
    // Parse the response
    QJsonObject responseObj = response.jsonData.object();
    
    // Check if there's an error in the response
    if (responseObj.contains("error")) {
        QString errorMessage = "Server error: " + responseObj["error"].toString();
        if (parent) {
            QMessageBox::warning(parent, "Server Error", errorMessage);
        }
        qWarning() << errorMessage;
        return false;
    }
    
    // Log success
    qDebug() << "Successfully created permission for file" << fileUuid 
             << "with recipient" << recipientUsername;
    
    return true;
}

/**
 * @brief Gets the list of users who have access to a specific file
 */
QStringList X3DHNetworkUtils::getFilePermissions(
    const QString& fileUuid,
    QWidget* parent) {
    
    QStringList permissionsList;
    
    // Validate input
    if (fileUuid.isEmpty()) {
        qWarning() << "Cannot retrieve permissions for empty file UUID";
        if (parent) {
            QMessageBox::warning(parent, "Error", "File UUID cannot be empty");
        }
        return permissionsList;
    }
    
    // Make the request to the server
    QString endpoint = QString("/api/permissions/%1").arg(fileUuid);
    // Convert QString to std::string before passing to get()
    RequestUtils::Response response = LoginSessionManager::getInstance().get(endpoint.toStdString(), QJsonObject());
    
    if (!response.success || response.jsonData.isEmpty()) {
        qWarning() << "Failed to retrieve file permissions:" 
                  << QString::fromStdString(response.errorMessage);
        if (parent) {
            QMessageBox::warning(parent, "Error", 
                                "Failed to retrieve file permissions");
        }
        return permissionsList;
    }
    
    // Extract usernames from the response
    QJsonObject jsonObj = response.jsonData.object();
    if (!jsonObj.contains("permissions") || !jsonObj["permissions"].isArray()) {
        qWarning() << "Invalid response format for file permissions";
        return permissionsList;
    }
    
    QJsonArray permissions = jsonObj["permissions"].toArray();
    for (const QJsonValue &val : permissions) {
        QJsonObject permObj = val.toObject();
        if (permObj.contains("username")) {
            permissionsList.append(permObj["username"].toString());
        }
    }
    
    qDebug() << "Retrieved" << permissionsList.size() << "permissions for file" << fileUuid;
    return permissionsList;
}

/**
 * @brief Sends one-time pre-keys to the server for secure communication
 */
bool X3DHNetworkUtils::uploadOneTimePreKeys(const QJsonArray& oneTimePreKeysJson, QWidget* parent) {
    // Create request JSON object
    QJsonObject requestData;
    requestData["otpks"] = oneTimePreKeysJson;
    
    qDebug() << "Sending" << oneTimePreKeysJson.size() << "one-time pre-keys to server";
    
    // Send to /add_otpks endpoint
    RequestUtils::Response response = LoginSessionManager::getInstance().post(ADD_OTPKS_ENDPOINT, requestData);
    
    // Check if request was successful
    if (response.success) {
        QJsonObject jsonObj = response.jsonData.object();
        int otpkCount = jsonObj["otpk_count"].toInt();
        
        qDebug() << "Successfully stored one-time pre-keys on server. Current count:" << otpkCount;
        return true;
    } else {
        if (parent) {
            QMessageBox::warning(parent, "OTPK Upload Warning", 
                "Failed to upload security keys to server. Some secure sharing features may not work properly.");
        }
        qWarning() << "Failed to send one-time pre-keys:" << QString::fromStdString(response.errorMessage);
        return false;
    }
}

/**
 * @brief Uploads a new signed pre-key and its signature to the server
 */
bool X3DHNetworkUtils::updateSignedPreKey(
    const QString& signedPreKeyPublic,
    const QString& signature,
    QWidget* parent) {
    
    // Validate inputs
    if (signedPreKeyPublic.isEmpty() || signature.isEmpty()) {
        if (parent) {
            QMessageBox::warning(parent, "Invalid Input", 
                                "Signed pre-key and signature cannot be empty.");
        }
        qWarning() << "Invalid input for signed pre-key update";
        return false;
    }
    
    // Prepare request data
    QJsonObject requestData;
    requestData["spk"] = signedPreKeyPublic;
    requestData["spk_signature"] = signature;
    
    qDebug() << "Sending updated signed pre-key to server";
    
    // Make the API request to update the signed pre-key
    RequestUtils::Response response = LoginSessionManager::getInstance().post(UPDATE_SPK_ENDPOINT, requestData);
    
    // Check if request was successful
    if (!response.success) {
        QString errorMessage = "Failed to update signed pre-key: " + QString::fromStdString(response.errorMessage);
        if (parent) {
            QMessageBox::warning(parent, "Update Error", errorMessage);
        }
        qWarning() << errorMessage;
        return false;
    }
    
    // Parse the response
    QJsonObject responseObj = response.jsonData.object();
    
    // Check if there's an error in the response
    if (responseObj.contains("error")) {
        QString errorMessage = "Server error: " + responseObj["error"].toString();
        if (parent) {
            QMessageBox::warning(parent, "Server Error", errorMessage);
        }
        qWarning() << errorMessage;
        return false;
    }
    
    // Log success
    qDebug() << "Successfully updated signed pre-key on the server";
    
    return true;
}

