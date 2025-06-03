#include "friend_storage_utils.h"
#include "core/loginsessionmanager.h"
#include "constants.h"
#include <QFile>
#include <QJsonDocument>
#include <QCoreApplication>
#include <QDir>
#include <QMessageBox>
#include <QDebug>

/**
 * @brief Builds the file path for a user's friends storage file
 * @param username The username for which to create the storage file path
 * @return The complete file path for the friend storage file
 */
QString FriendStorageUtils::buildFriendStorageFilePath(const QString& username) {
    QDir friendsDir(QDir(QCoreApplication::applicationDirPath()).filePath(friendsDirectory));
    if (!friendsDir.exists()) {
        if (!friendsDir.mkpath(".")) {
            qWarning() << "Failed to create directory:" << friendsDir;
        }
    }
    return friendsDir.filePath(friendsPath + username + jsonExtension);
}

/**
 * @brief Reads friend data from a JSON file
 * @param username The username whose friends file to read
 * @param parent Optional parent widget for displaying error messages
 * @return JSON object containing the friend data
 */
QJsonObject FriendStorageUtils::readFriendsJson(const QString& username, QWidget* parent) {
    QJsonObject friendsData;
    
    // Get the filepath from the username
    QString filepath = buildFriendStorageFilePath(username);
    
    if (!QFile::exists(filepath)) {
        return friendsData;
    }
    
    // Read file data
    QFile file(filepath);
    if (!file.open(QIODevice::ReadOnly)) {
        if (parent) {
            QMessageBox::warning(parent, "File Opening Error", 
                                "Failed to open friend file: " + file.errorString());
        }
        return friendsData;
    }
    
    // Read the existing data
    const QByteArray jsonData = file.readAll();
    file.close();
    
    // Parse existing JSON data
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    if (parseError.error == QJsonParseError::NoError && doc.isObject()) {
        friendsData = doc.object();
    } else if (!jsonData.isEmpty() && parent) {
        QMessageBox::warning(parent, "Parse Error", 
                            "Failed to parse friends data: " + parseError.errorString());
    }
    
    return friendsData;
}

/**
 * @brief Writes friend data to a JSON file
 * @param username The username whose friends file to write to
 * @param friendsData JSON object containing the friend data to save
 * @param parent Optional parent widget for displaying error messages
 * @return true if the write succeeded, false otherwise
 */
bool FriendStorageUtils::writeFriendsJson(const QString& username, const QJsonObject& friendsData, QWidget* parent) {
    // Get the filepath from the username
    QString filepath = buildFriendStorageFilePath(username);
    
    QJsonDocument updatedDoc(friendsData);
    QFile writeFile(filepath);
    
    // Create directory if needed before trying to write the file
    QDir dir = QFileInfo(filepath).dir();
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    
    if (!writeFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        if (parent) {
            QMessageBox::warning(parent, "File Writing Error", 
                               "Failed to write to friend file: " + writeFile.errorString());
        }
        return false;
    }
    
    writeFile.write(updatedDoc.toJson());
    writeFile.close();
    
    return true;
}

/**
 * @brief Saves a friend's username and public key pair to storage
 * @param username The friend's username
 * @param publicKey The friend's public key
 * @param parent Optional parent widget for displaying error messages
 * @return true if the save succeeded, false otherwise
 */
bool FriendStorageUtils::saveFriendPairToJSON(const QString& username, const QString& publicKey, QWidget* parent) {
    if (username.isEmpty()) {
        if (parent) {
            QMessageBox::warning(parent, "Error", "Cannot save friend with empty username.");
        }
        return false;
    }
    
    if (publicKey.isEmpty()) {
        if (parent) {
            QMessageBox::warning(parent, "Error", "Cannot save friend with empty public key.");
        }
        return false;
    }
    
    // Get the current logged in user
    QString currentUsername = LoginSessionManager::getInstance().getUsername();
    if (currentUsername.isEmpty()) {
        if (parent) {
            QMessageBox::warning(parent, "Error", "No logged-in user found. Cannot save friend.");
        }
        return false;
    }
    
    // Read existing data
    QJsonObject friendsData = readFriendsJson(currentUsername, parent);
    
    // Add or update username and public key pair
    friendsData[username] = publicKey;
    qDebug() << "Saving friend pair: " << username << " with public key: " << publicKey;
    
    // Write back to file
    return writeFriendsJson(currentUsername, friendsData, parent);
}

/**
 * @brief Retrieves a user's public key from the friends storage system
 * @param username The username whose public key to retrieve
 * @param parent Optional parent widget for displaying error messages
 * @return The user's public key as a QString, or empty string if not found
 */
QString FriendStorageUtils::getUserPublicKey(const QString& username, QWidget* parent) {
    // Use existing method to build the file path
    QString currentUser = LoginSessionManager::getInstance().getUsername();
    
    // Use existing method to read the JSON data - FIXED: Pass username not filepath
    QJsonObject friendsData = readFriendsJson(currentUser, parent);
    
    // Look for the specified username's public key in the friends data
    if (friendsData.contains(username)) {
        return friendsData[username].toString();
    }
    
    // If the key is not found, show a warning
    if (parent) {
        QMessageBox::warning(parent, "Error", "Public key for " + username + " not found in storage.");
    }
    
    return QString();
}
