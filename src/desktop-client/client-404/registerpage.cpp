#include "registerpage.h"
#include "pages.h"
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
    QWidget(parent),
    ui(new Ui::RegisterPage)
{
    ui->setupUi(this);

    ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
    ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);

    connect(ui->createAccountButton, &QPushButton::clicked, this, &RegisterPage::onCreateAccountClicked);
    connect(ui->showPasswordButton, &QPushButton::clicked, this, &RegisterPage::onShowPasswordClicked);
    connect(ui->goToLoginButton, &QPushButton::clicked, this, &RegisterPage::goToLoginRequested);
}

RegisterPage::~RegisterPage()
{
    delete ui;
}

void RegisterPage::onCreateAccountClicked()
{
    QString accountName = ui->accountNameLineEdit->text();
    QString password = ui->passwordLineEdit->text();
    QString confirmPassword = ui->confirmPasswordLineEdit->text();
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
        QMessageBox::information(this, "Warning", "Your password contains characters that may look different on other devices.");
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
    QByteArray saltRaw = QByteArray::fromBase64(salt.toUtf8()); // decode to raw bytes
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    string sAccountName = accountName.toStdString();
    string sPassword = password.toStdString();
    string pubKey = password.toStdString();
    string sSalt = salt.toStdString();

    deriveKeyFromPassword(sPassword, reinterpret_cast<const unsigned char*>(saltRaw.constData()), key, sizeof(key));

    saveKeysToJsonFile(this, pubKeyBase64, privKeyBase64, "keys.json");
    encryptAndSaveKey(this, privKeyBase64, key, accountName);


    //Debug prints
    cout << sAccountName << endl;
    cout << hashed << endl;
    cout << pubKeyBase64.toStdString() << endl;
    cout << privKeyBase64.toStdString() << endl;
    cout << "Salt: " << sSalt << endl;

    //Uncomment when server side is ready
    sendCredentials(sAccountName, hashed, pubKey, sSalt);


    QMessageBox::information(this, "Success", "Account created!");


    // Switch to main menu after registration
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(Pages::MainMenuIndex);
    }
}

void RegisterPage::onShowPasswordClicked()
{
    if (ui->passwordLineEdit->echoMode() == QLineEdit::Password) {
        ui->passwordLineEdit->setEchoMode(QLineEdit::Normal);
        ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Normal);
        ui->showPasswordButton->setText("Hide");
    } else {
        ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
        ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
        ui->showPasswordButton->setText("Show");
    }
}

void RegisterPage::sendCredentials(string name, string password, string publicKey, string salt)
{
    QJsonObject json;
    json["username"] = QString::fromStdString(name);
    json["hashed_password"] = QString::fromStdString(password);
    json["salt"] = QString::fromStdString(salt);
    QString base64PublicKey = QString::fromStdString(publicKey).toUtf8().toBase64();
    json["public_key"] = base64PublicKey;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl("http://gobbler.info:4004/sign_up"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = manager->post(request, jsonData);

    connect(reply, &QNetworkReply::finished, this, [reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray response = reply->readAll();
            cout << response.toStdString() << endl;
        } else {
           cout << "error: " << reply->errorString().toStdString() << endl;
        }
        reply->deleteLater();
    });

}
