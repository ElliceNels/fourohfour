#include "fileitemwidget.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include <QCoreApplication>
#include <QFile>
#include <QFileDialog>
#include <QDir>
#include <QFileInfo>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include "constants.h"
#include "crypto/encryptionhelper.h"
#include "utils/file_crypto_utils.h"
#include "utils/securebufferutils.h"
#include "utils/widget_utils.h"
#include "utils/file_sharing_manager_utils.h"
#include "utils/friend_storage_utils.h"

FileItemWidget::FileItemWidget(const QString &fileName, const QString &fileFormat, qint64 fileSize, const QString &owner, const bool isOwner, const QString& uuid, QWidget *parent)
    : QWidget(parent)
{
    this->fileExtension = fileFormat;
    this->fileUuid = uuid;
    this->fileSizeBytes = fileSize;
    this->isOwner = isOwner;  // Store isOwner as a member variable
    this->fileNameLabel = UIUtils::createElidedLabel(fileName + "." + fileFormat, fileNameLabelWidth, this);
    
    // Format file size for display
    QString formattedSize = formatFileSize(fileSize);
    this->fileSizeLabel = UIUtils::createElidedLabel(formattedSize, fileSizeLabelWidth, this);
    this->ownerLabel = UIUtils::createElidedLabel(owner, fileOwnerLabelWidth, this);

    // Buttons
    this->downloadButton = UIUtils::createIconButton(downloadIconPath, this);
    if(this->isOwner){  // Use the member variable instead of the parameter
        this->shareButton = UIUtils::createIconButton(shareIconPath, this);  // only owners can share files
        this->deleteButton = UIUtils::createIconButton(deleteIconPath, this);
    }
  
    connect(this->downloadButton, &QPushButton::clicked, this, &FileItemWidget::handleDownload);

    if (this->isOwner) {  // Use the member variable instead of the parameter
        connect(this->shareButton, &QPushButton::clicked, this, &FileItemWidget::handleShare); // only owners can share files
        connect(this->deleteButton, &QPushButton::clicked, this, &FileItemWidget::handleDelete);
    } 

    // Layout
    auto *layout = new QHBoxLayout(this);
    layout->addWidget(this->fileNameLabel);
    layout->addWidget(this->fileSizeLabel);
    layout->addWidget(this->ownerLabel);
    layout->addStretch();
    layout->addWidget(this->downloadButton);
    if (this->isOwner) {  // Use the member variable instead of the parameter
        layout->addWidget(this->shareButton);
        layout->addWidget(this->deleteButton);
    }


    this->setLayout(layout);

    this->setStyleSheet(Styles::FileItem);
}

// format file size in appropriate units
QString FileItemWidget::formatFileSize(qint64 bytes) const {
    if (bytes < FileUpload::MB) {
        double size = bytes / static_cast<double>(FileUpload::KB);
        return QString("%1 KB").arg(size, 0, 'f', 1);
    } else {
        double size = bytes / static_cast<double>(FileUpload::MB);
        return QString("%1 MB").arg(size, 0, 'f', 2);
    }
}

void FileItemWidget::handleDownload() {
    qDebug() << "Download clicked for file:" << this->fileNameLabel->toolTip() << " UUID:" << this->fileUuid;
    
    // Fetch the encrypted file from server
    QByteArray encryptedData;
    QJsonObject jsonResponse;
    if (!fetchEncryptedFileWithMetadata(encryptedData, jsonResponse)) {
        return; // Error already shown to user
    }
    
    // Get the file encryption key (either from local storage or via X3DH)
    auto fileKey = getFileKey(jsonResponse);
    if (!fileKey) {
        return; // Error already shown to user
    }
    
    // Process, decrypt and save the file
    processAndDecryptFile(encryptedData, fileKey.get());
}

std::unique_ptr<unsigned char[], SodiumZeroDeleter> FileItemWidget::getFileKey(const QJsonObject& jsonResponse) {
    auto fileKey = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    
    // Check if this is a shared file or owned file
    if (isOwner || !jsonResponse.contains("key_for_recipient")) {
        // This is an owned file - use regular key retrieval flow
        if (!FileCryptoUtils::getFileEncryptionKey(this->fileUuid, fileKey.get(), 
                                                crypto_aead_xchacha20poly1305_ietf_KEYBYTES, this)) {
            // Return empty unique_ptr instead of nullptr
            return std::unique_ptr<unsigned char[], SodiumZeroDeleter>(nullptr, SodiumZeroDeleter(0));
        }
    }
    else {
        // This is a shared file - use X3DH flow to get the decrypted key
        if (!getSharedFileKey(jsonResponse, fileKey.get())) {
            // Return empty unique_ptr instead of nullptr
            return std::unique_ptr<unsigned char[], SodiumZeroDeleter>(nullptr, SodiumZeroDeleter(0));
        }
    }
    
    return fileKey;
}

bool FileItemWidget::getSharedFileKey(const QJsonObject& jsonResponse, unsigned char* fileKey) {
    // Extract required parameters from the response
    QString senderEphemeralKey = jsonResponse["ephemeral_key"].toString();
    QByteArray encryptedKeyData = QByteArray::fromBase64(jsonResponse["key_for_recipient"].toString().toLatin1());
    QString recipientSignedPreKey = jsonResponse["spk"].toString();
    QString oneTimePreKey = jsonResponse["otpk"].toString();
    
    // Get sender's identity key (file owner's public key)
    QString senderIdentityKey;
    if (ownerLabel) {
        QString ownerUsername = ownerLabel->text();
        senderIdentityKey = FriendStorageUtils::getUserPublicKey(ownerUsername, this);
        if (senderIdentityKey.isEmpty()) {
            QMessageBox::critical(this, "Download Error", 
                "Failed to retrieve file owner's public key. Cannot decrypt file.");
            return false;
        }
    } else {
        QMessageBox::critical(this, "Download Error", "Cannot determine file owner");
        return false;
    }
    
    // Use FileSharingManagerUtils to get the decrypted file key
    return FileSharingManagerUtils::receiveSharedFile(
        this->fileUuid,
        senderIdentityKey,
        senderEphemeralKey,
        encryptedKeyData,
        recipientSignedPreKey,
        oneTimePreKey,
        fileKey,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        this
    );
}

bool FileItemWidget::processAndDecryptFile(const QByteArray& encryptedData, const unsigned char* fileKey) {
    // Extract nonce and ciphertext
    auto fileNonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    SecureVector fileCiphertext;
    if (!extractFileComponents(encryptedData, fileNonce, fileCiphertext)) {
        return false;
    }
    
    // Create metadata for authenticated decryption
    QByteArray metadataBytes = prepareFileMetadata();
    
    // Decrypt the file
    SecureVector decryptedFile;
    if (!decryptFile(fileCiphertext, fileKey, fileNonce, metadataBytes, decryptedFile)) {
        return false;
    }
    
    // Save the decrypted file
    saveDecryptedFile(decryptedFile);
    return true;
}

bool FileItemWidget::fetchEncryptedFile(QByteArray& encryptedData) {
    std::string downloadEndpoint = FILES_API_ENDPOINT + "/" + this->fileUuid.toStdString();
    RequestUtils::Response response = LoginSessionManager::getInstance().get(downloadEndpoint);
    
    if (!response.success) {
        QMessageBox::critical(this, "Download Error", 
            "Failed to download file: " + QString::fromStdString(response.errorMessage));
        return false;
    }
    
    QJsonObject jsonResponse = response.jsonData.object();
    if (!jsonResponse.contains("encrypted_file")) {
        QMessageBox::critical(this, "Download Error", "Invalid server response: missing encrypted file data");
        return false;
    }
    
    // Extract encrypted file data from response
    encryptedData = QByteArray::fromBase64(jsonResponse["encrypted_file"].toString().toLatin1());
    return true;
}

bool FileItemWidget::fetchEncryptedFileWithMetadata(QByteArray& encryptedData, QJsonObject& jsonResponse) {
    std::string downloadEndpoint = FILES_API_ENDPOINT + "/" + this->fileUuid.toStdString();
    RequestUtils::Response response = LoginSessionManager::getInstance().get(downloadEndpoint);
    
    if (!response.success) {
        QMessageBox::critical(this, "Download Error", 
            "Failed to download file: " + QString::fromStdString(response.errorMessage));
        return false;
    }
    
    jsonResponse = response.jsonData.object();
    if (!jsonResponse.contains("encrypted_file")) {
        QMessageBox::critical(this, "Download Error", "Invalid server response: missing encrypted file data");
        return false;
    }
    
    // Extract encrypted file data from response
    encryptedData = QByteArray::fromBase64(jsonResponse["encrypted_file"].toString().toLatin1());
    return true;
}

bool FileItemWidget::extractFileComponents(const QByteArray& encryptedData, 
                              std::unique_ptr<unsigned char[], SodiumZeroDeleter>& fileNonce,
                              SecureVector& fileCiphertext) {
    if (encryptedData.size() <= crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        QMessageBox::critical(this, "Error", "Encrypted file data is too small or corrupted");
        return false;
    }
    
    // Copy nonce data to secure buffer
    std::copy(encryptedData.constData(), 
              encryptedData.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 
              fileNonce.get());
    
    // Extract ciphertext
    const int fileCiphertextSize = encryptedData.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    fileCiphertext.resize(fileCiphertextSize);
    std::copy(encryptedData.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
              encryptedData.constData() + encryptedData.size(), 
              fileCiphertext.begin());
    
    return true;
}

QByteArray FileItemWidget::prepareFileMetadata() {
    QString fileName = this->fileNameLabel->toolTip();
    if (fileName.endsWith("." + this->fileExtension)) {
        fileName = fileName.left(fileName.length() - this->fileExtension.length() - 1);
    }
    
    return FileCryptoUtils::formatFileMetadata(
        fileName, this->fileExtension, this->fileSizeBytes);
}

bool FileItemWidget::decryptFile(const SecureVector& fileCiphertext,
                               const unsigned char* fileKey,
                               std::unique_ptr<unsigned char[], SodiumZeroDeleter>& fileNonce,
                               const QByteArray& metadataBytes,
                               SecureVector& decryptedFile) {
    EncryptionHelper crypto;
    try {
        decryptedFile = crypto.decrypt(
            fileCiphertext.data(),
            fileCiphertext.size(),
            fileKey,
            fileNonce.get(),
            reinterpret_cast<const unsigned char*>(metadataBytes.constData()),
            metadataBytes.size()
        );
        
        // No need to manually clean up or delete - the smart pointer will handle it
        return true;
        
    } catch (const std::exception& e) {
        // No need for manual cleanup - smart pointers handle it automatically
        QMessageBox::critical(this, "Error", 
            QString("Failed to decrypt file: %1").arg(e.what()));
        return false;
    }
}

void FileItemWidget::saveDecryptedFile(const SecureVector& decryptedFile) {
    // Extract the original filename without extension
    QString fileName = this->fileNameLabel->toolTip();
    if (fileName.endsWith("." + this->fileExtension)) {
        fileName = fileName.left(fileName.length() - this->fileExtension.length() - 1);
    }
    
    // Construct the full filename with extension
    QString fullFilename = fileName + "." + this->fileExtension;
    
    // Show save dialog with the original filename as default
    QString saveFilePath = QFileDialog::getSaveFileName(
        this, 
        "Save File", 
        QDir::homePath() + "/" + fullFilename,
        this->fileExtension.isEmpty() ? 
            "All Files (*)" : 
            QString("%1 Files (*.%2);;All Files (*)").arg(this->fileExtension.toUpper()).arg(this->fileExtension)
    );
    
    if (saveFilePath.isEmpty()) {
        // User cancelled the save dialog
        return;
    }
    
    // Ensure the filename has the correct extension
    if (!this->fileExtension.isEmpty() && !saveFilePath.endsWith("." + this->fileExtension)) {
        saveFilePath += "." + this->fileExtension;
    }
    
    QFile saveFile(saveFilePath);
    if (!saveFile.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "Error", 
            "Failed to open file for writing: " + saveFile.errorString());
        return;
    }
    
    // Write the decrypted data to file
    qint64 bytesWritten = saveFile.write(reinterpret_cast<const char*>(decryptedFile.data()), 
                                        static_cast<qint64>(decryptedFile.size()));
    saveFile.close();
    
    if (bytesWritten != static_cast<qint64>(decryptedFile.size())) {
        QMessageBox::critical(this, "Error", 
            "Failed to write complete file: " + saveFile.errorString());
        return;
    }
    
    QMessageBox::information(this, "Success", 
        QString("File downloaded and saved successfully as: %1").arg(QFileInfo(saveFilePath).fileName()));
}

void FileItemWidget::handleShare() {
    emit shareRequested(); 
}

void FileItemWidget::handleDelete() {
    if (UIUtils::confirmAction("Confirm Deletion", "Are you sure you want to delete this file?", this)) {
        // Construct the endpoint URL with the file UUID
        std::string deleteUrl = FILES_API_ENDPOINT + "/" + this->fileUuid.toStdString();
        
        RequestUtils::Response response = LoginSessionManager::getInstance().del(deleteUrl);
        
        // Check the response and show appropriate message
        if (response.success) {
            QMessageBox::information(this, "Success", response.jsonData.object().value("message").toString());
            emit fileDeleted(); // Emit the signal when deletion is successful to trigger UI refresh
        } else {
            QMessageBox::critical(this, "Error", 
                "Failed to delete file: " + QString::fromStdString(response.errorMessage));
        }
    }
}

