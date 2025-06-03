#include "uploadfilepage.h"
#include "ui/ui_uploadfilepage.h"
#include <qfileinfo.h>
#include <QFileDialog>
#include "crypto/encryptionhelper.h"
#include <QMessageBox>
#include <QJsonObject>
#include <qjsondocument.h>
#include <qstackedwidget.h>
#include "constants.h"
#include "utils/securevector.h"
#include "utils/securebufferutils.h"
#include "core/LoginSessionManager.h"
#include <QUuid>
#include "request_utils.h"
#include <QJsonArray>
#include <QJsonValue>
#include "utils/file_crypto_utils.h"

using namespace std;

UploadFilePage::UploadFilePage(QWidget *parent)
    : BasePage(parent)
    , ui(new Ui::UploadFilePage)
{
    qDebug() << "Constructing and setting up Upload File Page";
}

void UploadFilePage::preparePage(){
    qDebug() << "Preparing Upload File Page";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
}

void UploadFilePage::initialisePageUi(){
    this->ui->setupUi(this);
    this->ui->confirmButton->hide();
    this->ui->confirmLabel->hide();
}

void UploadFilePage::setupConnections(){
    connect(this->ui->backButton, &QPushButton::clicked, this, &UploadFilePage::goToMainMenuRequested);
}

void UploadFilePage::on_uploadButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Open File", "", "All Files (*.*)");

    if (!filePath.isEmpty()) {
        QFileInfo fileInfo(filePath);

          // Gets the metadata that won't be encrypted but will be authenticated
        QString baseName = fileInfo.completeBaseName();
        // Sanitize the filename by replacing any dots with underscores
        baseName.replace(".", "_");
        this->fileName = baseName;
        
        this->fileType = fileInfo.suffix();
        this->fileSize = fileInfo.size();  // originally in bytes

        // Account for encryption overhead when checking file size
        // Encryption adds nonce (24 bytes) + auth tag (~16 bytes) = ~40 bytes overhead
        if (this->fileSize > (FileUpload::SERVER_MAX_SIZE_BYTES - FileUpload::ENCRYPTION_OVERHEAD_BYTES)) {
            QMessageBox::warning(this, "Error", 
                QString("File size %1 bytes exceeds limit. Maximum allowed: %2 bytes (accounting for encryption overhead)")
                .arg(this->fileSize)
                .arg(FileUpload::SERVER_MAX_SIZE_BYTES - FileUpload::ENCRYPTION_OVERHEAD_BYTES));
            return;
        }

        
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, "Error", "Failed to open file");
            return;
        }

        // Gets the actual file data to be encrypted
        this->fileData = file.readAll();
        file.close();

        // Validate that we actually read the file data
        if (this->fileData.isEmpty() || this->fileSize == 0) {
            QMessageBox::warning(this, "Error", "File is empty or could not be read");
            return;
        }

        // Display file meta data
        this->ui->fileNameOutput->setText(this->fileName);
        this->ui->fileTypeOutput->setText("." + this->fileType);
        this->ui->fileSizeOutput->setText(QString::number(this->fileSize) + " bytes");

        // Show confirm label and instructions
        this->ui->confirmButton->show();
        this->ui->confirmLabel->show();
    }
}


QByteArray UploadFilePage::formatFileMetadata(){
    return FileCryptoUtils::formatFileMetadata(this->fileName, this->fileType, this->fileSize);
}

void UploadFilePage::tryEncryptAndUploadFile() {
    EncryptionHelper crypto;

    auto key = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();

    try {
        crypto.generateKey(key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        crypto.generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        const unsigned char* plaintext_ptr = reinterpret_cast<const unsigned char*>(this->fileData.constData());
        unsigned long long plaintext_len = static_cast<unsigned long long>(this->fileData.size());

        QByteArray metadataBytes = this->formatFileMetadata();
        const unsigned char* metadata_ptr = reinterpret_cast<const unsigned char*>(metadataBytes.constData());
        unsigned long long metadata_len = static_cast<unsigned long long>(metadataBytes.size());

        SecureVector ciphertext = crypto.encrypt(
            plaintext_ptr,
            plaintext_len,
            key.get(),
            nonce.get(),
            metadata_ptr,
            metadata_len
        );

        // Prepare data: [nonce][ciphertext]
        // This will be the data that is sent to the server
        SecureVector combinedData(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + ciphertext.size());

        copy(nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, combinedData.begin());
        copy(ciphertext.begin(), ciphertext.end(), combinedData.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        // Upload the file to server and get the UUID
        QString fileUuid = uploadFileToServer(combinedData);
        if (fileUuid.isEmpty()) {
            return; // Early return on failure or user choice not to overwrite
        }

        // Save using the server-provided UUID
        if (!FileCryptoUtils::saveKeyToLocalStorage(fileUuid, key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES, this)) {
            QMessageBox::warning(this, "Error", "Failed to save encryption key to local storage");
        }

    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Encryption Error", e.what());
    }
}

QString UploadFilePage::uploadFileToServer(const SecureVector& encryptedData, const QString& fileUuid, const QString& successMessage) {
    // Validate input data
    if (encryptedData.empty()) {
        QMessageBox::warning(this, "Error", "No encrypted data to upload");
        return QString();
    }
    
    // Create a JSON document in the format expected by the server
    QJsonObject fileObj;
    fileObj["filename"] = this->fileName;
    
    // Add UUID for overwrite if provided
    if (!fileUuid.isEmpty()) {
        fileObj["uuid"] = fileUuid;
    }
    // Convert SecureVector to base64 string
    QByteArray tempData(reinterpret_cast<const char*>(encryptedData.data()), static_cast<int>(encryptedData.size()));
    QByteArray base64Data = tempData.toBase64(QByteArray::Base64Option::Base64Encoding);
    tempData.clear(); // Clear binary data immediately
    
    // Base64 is strictly ASCII, so fromLatin1 is the correct choice
    QString base64String = QString::fromLatin1(base64Data);
    base64Data.clear(); // Clear immediately after use
    
    fileObj["contents"] = base64String;

    QJsonObject metadataObj;
    metadataObj["size"] = static_cast<double>(this->fileSize);
    metadataObj["format"] = this->fileType;

    QJsonObject requestPayload;
    requestPayload["file"] = fileObj;
    requestPayload["metadata"] = metadataObj;

    qDebug() << "Uploading file:" << this->fileName << "." << this->fileType
             << (fileUuid.isEmpty() ? "" : " with UUID: " + fileUuid);


    RequestUtils::Response response = LoginSessionManager::getInstance().post(UPLOAD_FILE_ENDPOINT, requestPayload);

    // Handle response
    if (response.success) {
        QJsonObject jsonResponse = response.jsonData.object();
        
        if (jsonResponse.contains("uuid")) {
            QString uuid = jsonResponse["uuid"].toString();
            
            // Use custom success message if provided, otherwise use default
            QString message = !successMessage.isEmpty() 
                ? successMessage 
                : "File uploaded successfully!";
            
            QMessageBox::information(this, "Success", message);
            return uuid;
        } else {
            QMessageBox::warning(this, "Warning", "File uploaded but no UUID returned");
            return QString();
        }
    } else {
        // Check for conflict (409) status - File with same name exists
        if (response.statusCode == 409) {
            QJsonObject jsonResponse = response.jsonData.object();
            if (jsonResponse.contains("uuid")) {
                QString existingUuid = jsonResponse["uuid"].toString();
                // Show dialog asking if user wants to overwrite
                if (showOverwriteConfirmation()) {
                    // Reupload with the UUID to overwrite
                    return uploadFileToServer(encryptedData, existingUuid, "File overwritten successfully!");
                } else {
                    // User chose not to overwrite
                    return QString(); // empty string is handled and the encryptedKeys file is not updated
                }
            }
        }
        
        // Log the detailed error information for debugging
        qDebug() << "Upload failed - Status:" << response.statusCode 
                 << "Error:" << QString::fromStdString(response.errorMessage);
        
        // Show a generic user-friendly message without exposing technical details
        QMessageBox::warning(this, "Error", 
            "Failed to upload file. Please check your connection and try again.");
        
        return QString();
    }
}

bool UploadFilePage::showOverwriteConfirmation() {
    QMessageBox msgBox;
    msgBox.setIcon(QMessageBox::Question);
    msgBox.setText("A file with the same name already exists.");
    msgBox.setInformativeText("Do you want to overwrite the existing file?\n\nIf you select 'No', you should rename your file locally and try uploading again.");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    
    // If user clicks No, show additional reminder
    int result = msgBox.exec();
    if (result == QMessageBox::No) {
        QMessageBox::information(this, "Upload Cancelled", 
                               "Please rename your file locally and try uploading again.");
    }
    return (result == QMessageBox::Yes);
}

QString UploadFilePage::reuploadWithUuid(const SecureVector& encryptedData, const QString& fileUuid) {
    // Simply call uploadFileToServer with the UUID and a custom success message
    return uploadFileToServer(encryptedData, fileUuid, "File overwritten successfully!");
}

void UploadFilePage::on_confirmButton_clicked(){

    // 
   tryEncryptAndUploadFile();

    // Clean up member variables and this->ui
    this->fileData.clear();
    this->fileName.clear();
    this->fileType.clear();
    this->fileSize = 0;

    this->ui->fileNameOutput->setText("-");
    this->ui->fileTypeOutput->setText("-");
    this->ui->fileSizeOutput->setText("-");

    this->ui->confirmButton->hide();
    this->ui->confirmLabel->hide();
}

UploadFilePage::~UploadFilePage()
{
    qDebug() << "Destroying Upload File Page";
    delete this->ui;
}
