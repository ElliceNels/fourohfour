#include "registerpage.h"
#include "ui_registerpage.h"
#include <QMessageBox>
#include "password_utils.h"
#include <iostream>
#include <QJsonObject>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <qstackedwidget.h>
#include "key_utils.h"
using namespace std;

RegisterPage::RegisterPage(QWidget *parent) :
    BasePage(parent),
    ui(new Ui::RegisterPage)
{
    qDebug() << "Constructing and setting up Register Page";
}

void RegisterPage::preparePage(){
    qDebug() << "Preparing Register Page";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
}

void RegisterPage::initialisePageUi(){
    this->ui->setupUi(this);
    this->ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
    this->ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
}

void RegisterPage::setupConnections(){
    connect(this->ui->createAccountButton, &QPushButton::clicked, this, &RegisterPage::onCreateAccountClicked);
    connect(this->ui->showPasswordButton, &QPushButton::clicked, this, &RegisterPage::onShowPasswordClicked);
    connect(this->ui->goToLoginButton, &QPushButton::clicked, this, &RegisterPage::goToLoginRequested);
}

void RegisterPage::onCreateAccountClicked()
{
    QString accountName = this->ui->accountNameLineEdit->text();
    QString password = this->ui->passwordLineEdit->text();
    QString confirmPassword = this->ui->confirmPasswordLineEdit->text();
    QSet<QString> dictionaryWords;

    dictionaryWords = loadDictionaryWords("../../common_passwords.txt"); //source: https://work2go.se/en/category/news/

    //Validation checks
    if (password != confirmPassword) {
        QMessageBox::warning(this, "Error", "Passwords do not match!");
        return;
    }
    if (password.length() < 8) {
        QMessageBox::warning(this, "Error", "Password must be at least 8 characters long.");
        return;
    }
    if (password.length() > 64) {
        QMessageBox::warning(this, "Error", "Password must be no more than 64 characters long.");
        return;
    }
    if (accountName.trimmed().isEmpty()) {
        QMessageBox::warning(this, "Error", "Username cannot be empty or only spaces.");
        return;
    }
    if (password.trimmed().isEmpty()) {
        QMessageBox::warning(this, "Error", "Password cannot be empty or only spaces.");
        return;
    }
    if (password.compare(accountName, Qt::CaseInsensitive) == 0) {
        QMessageBox::warning(this, "Error", "Password cannot be the same as your username.");
        return;
    }
    QString normalizedPassword = password.normalized(QString::NormalizationForm_KC);     // Unicode normalization
    if (password != normalizedPassword) {
        QMessageBox::warning(this, "Error", "Your password contains characters that may look different on other devices.");
    }
    if (dictionaryWords.contains(password.toLower())) {
        QMessageBox::warning(this, "Error", "Password is too common or easily guessable.");
        return;
    }




    //Hash password
    string hashed;

    hash_password(password.toStdString(), hashed);



    //Generate key pair and save locally
    QString pubKeyBase64, privKeyBase64;
    if (!generateSodiumKeyPair(pubKeyBase64, privKeyBase64)) {
        QMessageBox::critical(this, "Error", "libsodium initialization failed!");
        return;
    }



    QString salt = generateSalt(crypto_pwhash_SALTBYTES); //16 bytes
    QByteArray saltRaw = QByteArray(QByteArray::fromBase64(salt.toUtf8())); // decode to raw bytes
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    string sAccountName = accountName.toStdString();
    string sPassword = password.toStdString();
    string pubKey = password.toStdString();
    string sSalt = salt.toStdString();
    string* saltPtr = &sSalt;

    deriveKeyFromPassword(sPassword, reinterpret_cast<const unsigned char*>(saltRaw.constData()), key, sizeof(key));

    saveKeysToJsonFile(this, pubKeyBase64, privKeyBase64, "keys.json");
    encryptAndSaveKey(this, privKeyBase64, key, accountName);


    //Debug prints
    cout << sAccountName << endl;
    cout << hashed << endl;
    cout << pubKeyBase64.toStdString() << endl;
    cout << privKeyBase64.toStdString() << endl;
    cout << "Salt: " << *saltPtr << endl;

    //Uncomment when server side is ready
    //sendCredentials(sAccountName, sEmail, hashed, pubKey, sSalt);


    QMessageBox::information(this, "Success", "Account created!");


    // Switch to main menu after registration
    emit goToMainMenuRequested();
}

void RegisterPage::onShowPasswordClicked()
{
    if (this->ui->passwordLineEdit->echoMode() == QLineEdit::Password) {
        this->ui->passwordLineEdit->setEchoMode(QLineEdit::Normal);
        this->ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Normal);
        this->ui->showPasswordButton->setText("Hide");
    } else {
        this->ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
        this->ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
        this->ui->showPasswordButton->setText("Show");
    }
}

void RegisterPage::sendCredentials(string name, string email, string password, string publicKey, string salt)
{
    QJsonObject json;
    json["accountName"] = QString::fromStdString(name);
    json["hashedPassword"] = QString::fromStdString(password);
    json["publicKey"] = QString::fromStdString(publicKey);
    json["salt"] = QString::fromStdString(salt);

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl("https://gobbler.info"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = manager->post(request, jsonData);
}


RegisterPage::~RegisterPage()
{
    qDebug() << "Destroying Register Page";
    delete this->ui;
}
