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

FileItemWidget::FileItemWidget(const QString &fileName, const QString &fileFormat, qint64 fileSize, const QString &owner, const bool isOwner, const QString& uuid, QWidget *parent)
    : QWidget(parent)
{

    this->fileExtension = fileFormat;
    this->fileUuid = uuid;
    this->fileSizeBytes = fileSize;
    this->fileNameLabel = this->createElidedLabel(fileName + "." + fileFormat, fileNameLabelWidth);
    
    // Format file size for display
    QString formattedSize = formatFileSize(fileSize);
    this->fileSizeLabel = this->createElidedLabel(formattedSize, fileSizeLabelWidth);
    this->ownerLabel = this->createElidedLabel(owner, fileOwnerLabelWidth);

    // Buttons
    this->previewButton = createIconButton(previewIconPath);
    this->downloadButton = createIconButton(downloadIconPath);
    if(isOwner){
        this->shareButton = createIconButton(shareIconPath);  // only owners can share files
        this->deleteButton = createIconButton(deleteIconPath);
    }
  
    connect(this->downloadButton, &QPushButton::clicked, this, &FileItemWidget::handleDownload);

    if (isOwner) {
        connect(this->shareButton, &QPushButton::clicked, this, &FileItemWidget::handleShare); // only owners can share files
        connect(this->deleteButton, &QPushButton::clicked, this, &FileItemWidget::handleDelete);
    } 

    connect(this->previewButton, &QPushButton::clicked, this, &FileItemWidget::handlePreview);

    // Layout
    auto *layout = new QHBoxLayout(this);
    layout->addWidget(this->fileNameLabel);
    layout->addWidget(this->fileSizeLabel);
    layout->addWidget(this->ownerLabel);
    layout->addStretch();
    layout->addWidget(this->downloadButton);
    if (isOwner) {
        layout->addWidget(this->shareButton);
        layout->addWidget(this->deleteButton);
    }
    layout->addWidget(this->previewButton);


    this->setLayout(layout);

    this->setStyleSheet(Styles::FileItem);
}

QPushButton* FileItemWidget::createIconButton(const QString& iconPath) {
    QPushButton* button = new QPushButton();
    button->setIcon(QIcon(iconPath));
    button->setIconSize(QSize(20, 20));
    button->setFixedSize(30, 30);
    button->setStyleSheet(Styles::TransparentButton);
    return button;
}

QLabel* FileItemWidget::createElidedLabel(const QString &text, int width) {
    QLabel *label = new QLabel(text);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    label->setMinimumWidth(width);
    label->setMaximumWidth(width);
    label->setWordWrap(false);
    label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    label->setToolTip(text);

    QFontMetrics metrics(label->font());
    QString elided = metrics.elidedText(text, Qt::ElideRight, width * truncationFactor);
    label->setText(elided);

    return label;
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
    if (!fetchEncryptedFile(encryptedData)) {
        return; // Error already shown to user within fetchEncryptedFile
    }
    
    // Get file encryption key from local storage
    auto fileKey = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    if (!FileCryptoUtils::getFileEncryptionKey(this->fileUuid, fileKey.get(), 
                                             crypto_aead_xchacha20poly1305_ietf_KEYBYTES, this)) {
        return; // Error already shown to user within getFileEncryptionKey
    }
    
    // Extract nonce and ciphertext and prepare for decryption
    auto fileNonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    SecureVector fileCiphertext;
    if (!extractFileComponents(encryptedData, fileNonce, fileCiphertext)) {
        return; // Error already shown to user within extractFileComponents
    }
    
    // Create metadata for authenticated decryption
    QByteArray metadataBytes = prepareFileMetadata();
    
    // Decrypt the file
    SecureVector decryptedFile;
    if (!decryptFile(fileCiphertext, fileKey.get(), fileNonce, metadataBytes, decryptedFile)) {
        return; // Error already shown to user within decryptFile
    }
    
    // Save the decrypted file
    saveDecryptedFile(decryptedFile);
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

bool FileItemWidget::confirmAction(const QString& title, const QString& text) {
    QMessageBox msgBox;
    msgBox.setWindowTitle(title);
    msgBox.setText(text);
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    
    return (msgBox.exec() == QMessageBox::Yes);
}

void FileItemWidget::handleDelete() {
    if (confirmAction("Confirm Deletion", "Are you sure you want to delete this file?")) {
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

void FileItemWidget::handlePreview() {
    // preview logic here
    qDebug() << "Preview clicked for file:" << this->fileNameLabel->toolTip();
}
