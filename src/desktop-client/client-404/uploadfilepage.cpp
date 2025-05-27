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

void UploadFilePage::encryptUploadedFile() {

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

    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Encryption Error", e.what());
    }
}


void UploadFilePage::on_confirmButton_clicked(){

    encryptUploadedFile();
    QMessageBox::information(this, "Success", "File uploaded successfully!");

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

