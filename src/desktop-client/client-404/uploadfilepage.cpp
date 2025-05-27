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


UploadFilePage::UploadFilePage(QWidget *parent)
    : BasePage(parent)
    , ui(new Ui::UploadFilePage)
{
    qDebug() << "Constructing and setting up Upload File Page";
}

void UploadFilePage::preparePage(){
    qDebug() << "Preparing Upload File Page";
    initialisePageUi();    // Will call the derived class implementation
    setupConnections();    // Will call the derived class implementation
}

void UploadFilePage::initialisePageUi(){
    ui->setupUi(this);
    ui->confirmButton->hide();
    ui->confirmLabel->hide();
}

void UploadFilePage::setupConnections(){
    connect(ui->backButton, &QPushButton::clicked, this, &UploadFilePage::goToMainMenuRequested);
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

        if (fileSize > MAX_FILE_SIZE_BYTES) {
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
        ui->fileNameOutput->setText(fileName);
        ui->fileTypeOutput->setText("." + fileType);
        ui->fileSizeOutput->setText(QString::number(fileSize) + " bytes");

        // Show confirm label and instructions
        ui->confirmButton->show();
        ui->confirmLabel->show();
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

void UploadFilePage::encryptUploadedFile(){
    EncryptionHelper crypto;

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    try {

        crypto.generateKey(key, sizeof(key));
        crypto.generateNonce(nonce, sizeof(nonce));

        const unsigned char* plaintext_ptr = reinterpret_cast<const unsigned char*>(this->fileData.constData());
        unsigned long long plaintext_len = static_cast<unsigned long long>(this->fileData.size());

        QByteArray metadataBytes = formatFileMetadata();
        const unsigned char* metadata_ptr = reinterpret_cast<const unsigned char*>(metadataBytes.constData());
        unsigned long long metadata_len = static_cast<unsigned long long>(metadataBytes.size());

        vector<unsigned char> ciphertext = crypto.encrypt(
            plaintext_ptr,
            plaintext_len,
            key,
            nonce,
            metadata_ptr,
            metadata_len
            );

    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Encryption Error", e.what());
    }
    sodium_memzero(key, sizeof(key));
    sodium_memzero(nonce, sizeof(nonce));
}


void UploadFilePage::on_confirmButton_clicked(){

    encryptUploadedFile();
    QMessageBox::information(this, "Success", "File uploaded successfully!");

    // Clean up member variables and ui
    this->fileData.clear();
    this->fileName.clear();
    this->fileType.clear();
    this->fileSize = 0;

    ui->fileNameOutput->setText("-");
    ui->fileTypeOutput->setText("-");
    ui->fileSizeOutput->setText("-");

    ui->confirmButton->hide();
    ui->confirmLabel->hide();
}

UploadFilePage::~UploadFilePage()
{
    qDebug() << "Destroying Upload File Page";
    delete ui;
}

