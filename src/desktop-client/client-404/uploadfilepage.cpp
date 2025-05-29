#include "uploadfilepage.h"
#include "ui_uploadfilepage.h"
#include <qfileinfo.h>
#include <QFileDialog>
#include "encryptionhelper.h"
#include <QMessageBox>
#include <QJsonObject>
#include <qjsondocument.h>
#include <qstackedwidget.h>
#include "constants.h"
#include "securevector.h"
#include "securebufferutils.h"
#include "loginsessionmanager.h"
#include <QUuid>

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
        this->fileName = fileInfo.completeBaseName();
        this->fileType = fileInfo.suffix();
        this->fileSize = fileInfo.size();  // originally in bytes

        if (this->fileSize > MAX_FILE_SIZE_BYTES) {
            QMessageBox::warning(this, "Error", "This file exceeds the 100MB limit");
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

    // Converting the file metadata to this format ensures consistency.
    // The server will return the metadata as a JSON object, which will be authenticated during decryption.
    // To keep it consistent on both ends, we also format it as a JSON object before encryption.

    QJsonObject fileMetaData;
    fileMetaData.insert("fileName", this->fileName);
    fileMetaData.insert("fileType", this->fileType);
    fileMetaData.insert("fileSize", this->fileSize);

    QJsonDocument metadataDoc(fileMetaData);
    QByteArray metadataBytes = metadataDoc.toJson(QJsonDocument::Compact);

    return metadataBytes;
}

bool UploadFilePage::encryptUploadedFile() {

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

    copy(nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, combinedData.begin());    // Copy nonce to beginning
    copy(ciphertext.data(), ciphertext.data() + ciphertext.size(),  combinedData.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);  // Move ciphertext data to avoid copying


    // After sending to the server, we will recieve a uuid for the file as a string.
    QString fileUuid = QUuid::createUuid().toString(QUuid::WithoutBraces);

    return SaveKeyToLocalStorage(fileUuid, key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES); // expected key length that configured when creating the buffer

    } catch (const exception &e) {
        QMessageBox::critical(this, "Encryption Error", e.what());
        return false;
    }
}

bool UploadFilePage::SaveKeyToLocalStorage(const QString &fileUuid, const unsigned char *key, size_t keyLen) {
    // Validate inputs
    if (!validateKeyParameters(key, keyLen)) {
        return false;
    }

    // Get master key and validate it
    const SecureVector masterKey = LoginSessionManager::getInstance().getMasterKey();
    if (!validateMasterKey(masterKey)) {
        return false;
    }

    // Get file path for user's key storage
    const QString filepath = buildKeyStorageFilePath();
    
    // Read and decrypt key storage file
    QByteArray jsonData;
    if (!readAndDecryptKeyStorage(filepath, masterKey, jsonData)) {
        return false;
    }
    
    // Update JSON with new key
    QByteArray updatedJsonData;
    if (!addKeyToJsonStorage(jsonData, fileUuid, key, keyLen, updatedJsonData)) {
        return false;
    }
    
    // Encrypt and save updated storage
    return encryptAndSaveKeyStorage(filepath, updatedJsonData, masterKey);
}

// Validate key parameters 
bool UploadFilePage::validateKeyParameters(const unsigned char *key, size_t keyLen) {
    if (key == nullptr || keyLen != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        QMessageBox::warning(this, "Error",
                             QString("Invalid file encryption key length: expected %1 bytes, got %2 bytes")
                                 .arg(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
                                 .arg(keyLen));
        return false;
    }
    return true;
}

// Validate master key
bool UploadFilePage::validateMasterKey(const SecureVector &masterKey) {
    if (masterKey.empty() || masterKey.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        QMessageBox::warning(this, "Error",
                             QString("Invalid master key length: expected %1 bytes, got %2 bytes")
                                 .arg(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
                                 .arg(masterKey.size()));
        return false;
    }
    return true;
}

// Build the key storage file path
QString UploadFilePage::buildKeyStorageFilePath() {
    const QString username = LoginSessionManager::getInstance().getUsername();
    return QCoreApplication::applicationDirPath() + keysPath + username + binaryExtension;
}

// Read and decrypt the key storage file
bool UploadFilePage::readAndDecryptKeyStorage(const QString &filepath, 
                                             const SecureVector &masterKey,
                                             QByteArray &jsonData) {
    // Check if file exists
    if (!QFile::exists(filepath)) {
        QMessageBox::warning(this, "Decryption Error", "Could not find encrypted keys file.");
        return false;
    }

    // Read file data
    QFile file(filepath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Decryption Error", 
                            "Failed to open encrypted keys file: " + file.errorString());
        return false;
    }
    const QByteArray fileData = file.readAll();
    file.close();

    // Validate data size
    const int ciphertextSize = fileData.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (ciphertextSize <= 0) {
        QMessageBox::warning(this, "Decryption Error", "Encrypted file is too small. It may be corrupted.");
        return false;
    }

    // Extract components
    SecureVector ciphertext(ciphertextSize);
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    
    copy(fileData.constData(), fileData.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, nonce.get());
    copy(fileData.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, fileData.constData() + fileData.size(), ciphertext.begin());

    // Decrypt data
    EncryptionHelper crypto;
    SecureVector plaintext;
    try {
        plaintext = crypto.decrypt(
            ciphertext.data(),
            ciphertextSize,
            masterKey.data(),
            nonce.get(),
            nullptr,
            0
        );
        
        jsonData = QByteArray(reinterpret_cast<const char*>(plaintext.data()),
                              static_cast<int>(plaintext.size()));

        // DELETE BEFORE MERGE
        QJsonDocument debugDoc = QJsonDocument::fromJson(jsonData);
        if (debugDoc.isObject()) {
            qDebug().noquote() << "Decrypted JSON Data:";
            qDebug().noquote() << QJsonDocument(debugDoc).toJson(QJsonDocument::Indented);
        } else {
            qDebug() << "Decrypted JSON is not a valid object";
        }
        
        return true;
    } catch (const exception& e) {
        QMessageBox::critical(this, "Decryption Error", 
                             QString("Decryption failed: %1").arg(e.what()));
        return false;
    }
}

// Add a key to the JSON storage
bool UploadFilePage::addKeyToJsonStorage(const QByteArray &jsonData, const QString &fileUuid, const unsigned char *key, size_t keyLen, QByteArray &updatedJsonData) {
    // Parse JSON
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        QMessageBox::warning(this, "Error",
                            QString("Failed to parse JSON: %1").arg(parseError.errorString()));
        return false;
    }

    // Update JSON structure
    QJsonObject json = doc.isObject() ? doc.object() : QJsonObject();
    QJsonObject filesObject = json.contains("files") ? json["files"].toObject() : QJsonObject();
    
    // Convert key to base64
    QByteArray keyBytes(reinterpret_cast<const char*>(key), keyLen);
    filesObject[fileUuid] = QString(keyBytes.toBase64());
    
    json["files"] = filesObject;
    doc.setObject(json);
    
    // Convert back to bytes
    updatedJsonData = doc.toJson(QJsonDocument::Compact);
    return true;
}

// Encrypt and save the updated key storage
bool UploadFilePage::encryptAndSaveKeyStorage(const QString &filepath, const QByteArray &jsonData, const SecureVector &masterKey) {
    EncryptionHelper crypto;
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    crypto.generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    
    // Encrypt data
    SecureVector ciphertext = crypto.encrypt(
        reinterpret_cast<const unsigned char*>(jsonData.constData()),
        jsonData.size(),
        masterKey.data(),
        nonce.get(),
        nullptr,
        0
    );
    
    // Prepare data for saving: [nonce][ciphertext]
    SecureVector combinedData(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + ciphertext.size());

    copy(nonce.get(), nonce.get() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, combinedData.begin());
    copy(ciphertext.data(), ciphertext.data() + ciphertext.size(), combinedData.begin() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    
    // Save file
    QFile file(filepath);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Encryption Error", 
                            "Failed to open file for writing: " + file.errorString());
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(combinedData.data()), static_cast<qint64>(combinedData.size()));
    file.close();
    
    return true;
}



void UploadFilePage::on_confirmButton_clicked(){

   if (encryptUploadedFile()) {
        QMessageBox::information(this, "Success", "File uploaded successfully!");
   }

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

