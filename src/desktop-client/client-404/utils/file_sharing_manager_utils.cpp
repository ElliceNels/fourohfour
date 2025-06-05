#include "file_sharing_manager_utils.h"
#include "utils/shared_secret_utils.h"
#include "utils/x3dh_network_utils.h"
#include "utils/file_sharing_utils.h"
#include "utils/friend_storage_utils.h"
#include "utils/widget_utils.h"
#include "core/loginsessionmanager.h"
#include <QMessageBox>
#include <QDebug>
#include <QApplication>

bool FileSharingManagerUtils::shareFileWithUser(
    const QString& fileUuid,
    const QString& recipientUsername,
    const QString& recipientPublicKey,
    QWidget* parent) {
    
    if (fileUuid.isEmpty() || recipientUsername.isEmpty() || recipientPublicKey.isEmpty()) {
        showErrorMessage(parent, "Invalid Input", 
                        "File UUID, recipient username, and public key are required.");
        return false;
    }
    
    // Get current user's identity key
    showProgressMessage(parent, "Retrieving identity keys...");
    QString senderIdentityKey = FriendStorageUtils::getUserPublicKey(
        LoginSessionManager::getInstance().getUsername(), parent);
        
    if (senderIdentityKey.isEmpty()) {
        showErrorMessage(parent, "Key Error", "Could not retrieve sender's identity key.");
        return false;
    }
    
    // Step 1: Generate shared secret using X3DH protocol
    showProgressMessage(parent, "Establishing secure connection with recipient...");
    SecureVector sharedSecret;
    QString ephemeralPublicKey;
    bool usedOneTimePrekey;
    QString usedPreKeyId;
    
    bool secretGenerated = SharedSecretUtils::generateSenderSharedSecret(
        recipientUsername,
        recipientPublicKey,
        sharedSecret,
        ephemeralPublicKey,
        usedOneTimePrekey,
        usedPreKeyId,
        parent
    );
    
    if (!secretGenerated || sharedSecret.empty()) {
        showErrorMessage(parent, "Security Error", 
                        "Failed to establish secure connection with recipient.");
        return false;
    }
    
    // Step 2: Encrypt the file key using the shared secret
    showProgressMessage(parent, "Encrypting file key...");
    QByteArray encryptedKeyData;
    
    bool keyEncrypted = SharedSecretUtils::encryptFileKeyWithSharedSecret(
        sharedSecret,
        fileUuid,
        senderIdentityKey,
        recipientPublicKey,
        encryptedKeyData,
        parent
    );
    
    if (!keyEncrypted || encryptedKeyData.isEmpty()) {
        showErrorMessage(parent, "Encryption Error", "Failed to encrypt file key.");
        return false;
    }
    
    // Step 3: Create permission on the server
    showProgressMessage(parent, "Creating permission...");
    bool permissionCreated = X3DHNetworkUtils::createPermission(
        fileUuid,
        recipientUsername,
        encryptedKeyData,
        usedPreKeyId,
        ephemeralPublicKey,
        parent
    );
    
    if (!permissionCreated) {
        showErrorMessage(parent, "Permission Error", 
                        "Failed to create file permission for recipient.");
        return false;
    }
    
    // Clear sensitive data
    sodium_memzero(sharedSecret.data(), sharedSecret.size());
    
    showProgressMessage(parent, "File shared successfully!");
    qDebug() << "Successfully shared file" << fileUuid << "with user" << recipientUsername;
    
    return true;
}

void FileSharingManagerUtils::showProgressMessage(QWidget* parent, const QString& message) {
    qDebug() << message;
    if (parent) {
        // Use the parent widget's status bar if available
        QMetaObject::invokeMethod(parent, "showStatusMessage", 
                                 Qt::QueuedConnection, 
                                 Q_ARG(QString, message));
        
        // Process events to update UI
        QApplication::processEvents();
    }
}

void FileSharingManagerUtils::showErrorMessage(QWidget* parent, const QString& title, const QString& message) {
    qWarning() << title << ":" << message;
    if (parent) {
        QMessageBox::warning(parent, title, message);
    }
}
