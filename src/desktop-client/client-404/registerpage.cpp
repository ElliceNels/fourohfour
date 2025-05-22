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
}

RegisterPage::~RegisterPage()
{
    delete ui;
}

void RegisterPage::onCreateAccountClicked()
{
    QString accountName = ui->accountNameLineEdit->text();
    QString email = ui->emailLineEdit->text();
    QString password = ui->passwordLineEdit->text();
    QString confirmPassword = ui->confirmPasswordLineEdit->text();


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
    // Unicode normalization
    QString normalizedPassword = password.normalized(QString::NormalizationForm_KC);
    if (password != normalizedPassword) {
        QMessageBox::information(this, "Warning", "Your password contains characters that may look different on other devices.");
    }


    //Hash password and convert to strings
    string sAccountName = accountName.toStdString();
    string sEmail = email.toStdString();
    string sPassword = password.toStdString();

    string hashed;

    hash_password(sPassword, hashed);



    //Generate key pair and save locally
    QString pubKeyBase64, privKeyBase64;
    if (!generateSodiumKeyPair(pubKeyBase64, privKeyBase64)) {
        QMessageBox::critical(this, "Error", "libsodium initialization failed!");
        return;
    }

    saveKeyToFile(this, pubKeyBase64, "public_key.txt");
    saveKeyToFile(this, privKeyBase64, "private_key.txt");


    //Debug prints
    cout << sAccountName << endl;
    cout << sEmail << endl;
    cout << hashed << endl;
    cout << pubKeyBase64.toStdString() << endl;
    cout << privKeyBase64.toStdString() << endl;

    //Uncomment when server side is ready
    //sendCredentials(sAccountName, sEmail, hashed, pubKeyBase64);


    QMessageBox::information(this, "Success", "Account created!");
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

void RegisterPage::sendCredentials(string name, string email, string password, string publicKey)
{
    QJsonObject json;
    json["accountName"] = QString::fromStdString(name);
    json["email"] = QString::fromStdString(email);
    json["hashedPassword"] = QString::fromStdString(password);
    json["publicKey"] = QString::fromStdString(publicKey);

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl("https://gobbler.info"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = manager->post(request, jsonData);
}
