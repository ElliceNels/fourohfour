#include "file_sharing_manager_utils.h"
#include "utils/shared_secret_utils.h"
#include "utils/x3dh_network_utils.h"
#include "utils/file_sharing_utils.h"
#include "utils/friend_storage_utils.h"
#include "utils/file_crypto_utils.h"  // Fixed: removed period, added slash
#include "utils/widget_utils.h"
#include "utils/securebufferutils.h"
#include "crypto/encryptionhelper.h"
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

bool FileSharingManagerUtils::receiveSharedFile(
    const QString& fileUuid,
    const QString& senderIdentityKey,
    const QString& senderEphemeralKey,
    const QByteArray& encryptedKeyData,
    const QString& recipientSignedPreKey,
    const QString& oneTimePreKey,
    unsigned char* fileKey,
    size_t fileKeySize,
    QWidget* parent) {
    
    if (fileUuid.isEmpty() || senderIdentityKey.isEmpty() || senderEphemeralKey.isEmpty() ||
        encryptedKeyData.isEmpty() || recipientSignedPreKey.isEmpty() || 
        oneTimePreKey.isEmpty() || fileKey == nullptr || 
        fileKeySize < crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        showErrorMessage(parent, "Invalid Input", "Required parameters missing for file key decryption");
        return false;
    }
    
    // Get recipient's public key (this user's key)
    showProgressMessage(parent, "Retrieving identity keys...");
    QString recipientIdentityKey = FriendStorageUtils::getUserPublicKey(
        LoginSessionManager::getInstance().getUsername(), parent);
    
    if (recipientIdentityKey.isEmpty()) {
        showErrorMessage(parent, "Key Error", "Could not retrieve recipient's identity key");
        return false;
    }
    
    // Step 1: Generate the shared secret using X3DH protocol (recipient side)
    showProgressMessage(parent, "Generating shared secret...");
    SecureVector sharedSecret = SharedSecretUtils::generateRecipientSharedSecret(
        senderIdentityKey,
        senderEphemeralKey,
        recipientSignedPreKey,
        oneTimePreKey,
        true,  // Remove used one-time prekey
        parent
    );
    
    if (sharedSecret.empty()) {
        showErrorMessage(parent, "Security Error", "Failed to generate shared secret for decryption");
        return false;
    }
    
    // Step 2: Decrypt the file encryption key using the shared secret
    showProgressMessage(parent, "Decrypting file key...");
    bool keyDecrypted = SharedSecretUtils::decryptFileKeyWithSharedSecret(
        sharedSecret,
        encryptedKeyData,
        senderIdentityKey,
        recipientIdentityKey,
        fileKey,
        fileKeySize,
        parent
    );
    
    if (!keyDecrypted) {
        showErrorMessage(parent, "Decryption Error", "Failed to decrypt file key");
        return false;
    }
    
    // Clear sensitive data
    sodium_memzero(sharedSecret.data(), sharedSecret.size());
    
    showProgressMessage(parent, "File key decrypted successfully!");
    qDebug() << "Successfully decrypted file key for shared file" << fileUuid;
    
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
