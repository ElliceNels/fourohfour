#include "friend_storage_utils.h"
#include "core/loginsessionmanager.h"
#include "constants.h"
#include <QFile>
#include <QJsonDocument>
#include <QCoreApplication>
#include <QDir>
#include <QMessageBox>
#include <QDebug>



QString FriendStorageUtils::buildFriendStorageFilePath(const QString& username) {
    QString dirPath = QCoreApplication::applicationDirPath() + friendsPath;
    QDir dir(dirPath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    return dirPath + username + jsonExtension;
}

QJsonObject FriendStorageUtils::readFriendsJson(const QString& filepath, QWidget* parent) {
    QJsonObject friendsData;
    
    if (!QFile::exists(filepath)) {
        // Create the file if it doesn't exist
        QFile file(filepath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            if (parent) {
                QMessageBox::warning(parent, "Error", "Could not create friend storage file.");
            }
            return friendsData;
        }
        file.close();
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

bool FriendStorageUtils::writeFriendsJson(const QString& filepath, const QJsonObject& friendsData, QWidget* parent) {
    QJsonDocument updatedDoc(friendsData);
    QFile writeFile(filepath);
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

bool FriendStorageUtils::saveFriendPairToJSON(const QString& username, const QString& publicKey, QWidget* parent) {
    // Get the current logged in user
    QString currentUsername = LoginSessionManager::getInstance().getUsername();
    // Get the filepath
    QString filepath = buildFriendStorageFilePath(currentUsername);
    
    // Read existing data
    QJsonObject friendsData = readFriendsJson(filepath, parent);
    
    // Add or update username and public key pair
    friendsData[username] = publicKey;
    qDebug() << "Saving friend pair: " << username << " with public key: " << publicKey;
    
    // Write back to file
    return writeFriendsJson(filepath, friendsData, parent);
}
