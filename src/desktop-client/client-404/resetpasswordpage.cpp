#include "resetpasswordpage.h"
#include "pages.h"
#include "ui_resetpasswordpage.h"
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
#include "loginsessionmanager.h"
#include <QUrl>
#include <QDebug>
#include <qstackedwidget.h>
#include "qwidget.h"
using namespace std;

ResetPasswordPage::ResetPasswordPage(QWidget *parent) :
    BasePage(parent),
    ui(new Ui::ResetPasswordPage)
{
   qDebug() << "Constructing and setting up Password Reset Page";

}

void ResetPasswordPage::preparePage(){
    qDebug() << "Preparing Register Page";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
}

void ResetPasswordPage::initialisePageUi(){
     ui->setupUi(this);
    ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
    ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
    ui->oldPasswordLineEdit->setEchoMode(QLineEdit::Password);
}

void ResetPasswordPage::setupConnections(){
    connect(ui->updatePasswordButton, &QPushButton::clicked, this, &::ResetPasswordPage::onUpdatePasswordClicked);
    connect(ui->showPasswordButton, &QPushButton::clicked, this, &ResetPasswordPage::onShowPasswordClicked);
}

ResetPasswordPage::~ResetPasswordPage()
{
    delete ui;
}

void ResetPasswordPage::onUpdatePasswordClicked()
{
    QString oldPassword = ui->oldPasswordLineEdit->text();
    QString newPassword = ui->passwordLineEdit->text();
    QString confirmPassword = ui->confirmPasswordLineEdit->text();
    QSet<QString> dictionaryWords;

    dictionaryWords = loadDictionaryWords("../../common_passwords.txt"); //source: https://work2go.se/en/category/news/
    //QString username = LoginSessionManager::getInstance().getUsername();


    //Validation checks
    if (newPassword != confirmPassword) {
        QMessageBox::warning(this, "Error", "New passwords do not match!");
        return;
    }
    if (newPassword.length() < 8) {
        QMessageBox::warning(this, "Error", "Password must be at least 8 characters long.");
        return;
    }
    if (newPassword.length() > 64) {
        QMessageBox::warning(this, "Error", "Password must be no more than 64 characters long.");
        return;
    }
    if (newPassword.trimmed().isEmpty()) {
        QMessageBox::warning(this, "Error", "Password cannot be empty or only spaces.");
        return;
    }
    // if (password.compare(accountName, Qt::CaseInsensitive) == 0) {
    //     QMessageBox::warning(this, "Error", "Password cannot be the same as your username.");
    //     return;
    // }
    QString normalizedPassword = newPassword.normalized(QString::NormalizationForm_KC);     // Unicode normalization
    if (newPassword != normalizedPassword) {
        QMessageBox::information(this, "Warning", "Your password contains characters that may look different on other devices.");
    }
    if (dictionaryWords.contains(newPassword.toLower())) {
        QMessageBox::warning(this, "Error", "Password is too common or easily guessable.");
        return;
    }

    //Hash password
    string hashed;
    hash_password(newPassword.toStdString(), hashed);


    //fetchAndStoreSalt();
    oldSalt =  generateSalt(crypto_pwhash_SALTBYTES);

    QString newSalt = generateSalt(crypto_pwhash_SALTBYTES); //16 bytes
    QByteArray newSaltRaw = QByteArray::fromBase64(newSalt.toUtf8()); // decode to raw bytes

    //decryptAndReencryptUserFile(username, oldPassword, oldSalt, newPassword, newSalt);

    //sendCredentials(hashed, newSalt.toStdString(););


    QMessageBox::information(this, "Success", "Password updated!");


    // Switch to main menu after reset
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(Pages::MainMenuIndex);
    }
}

void ResetPasswordPage::onShowPasswordClicked()
{
    if (ui->passwordLineEdit->echoMode() == QLineEdit::Password) {
        ui->passwordLineEdit->setEchoMode(QLineEdit::Normal);
        ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Normal);
        ui->oldPasswordLineEdit->setEchoMode(QLineEdit::Normal);
        ui->showPasswordButton->setText("Hide");
    } else {
        ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
        ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
        ui->oldPasswordLineEdit->setEchoMode(QLineEdit::Normal);
        ui->showPasswordButton->setText("Show");
    }
}

void ResetPasswordPage::sendCredentials(string password, string salt)
{
    QJsonObject json;
    json["hashedPassword"] = QString::fromStdString(password);
    json["salt"] = QString::fromStdString(salt);

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl("http://gobbler.info:4004/change_password"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = manager->post(request, jsonData);
}


void ResetPasswordPage::fetchAndStoreSalt()
{
    QNetworkAccessManager* manager = new QNetworkAccessManager();

    QNetworkRequest request(QUrl("http://gobbler.info:4004/get_current_user"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply* reply = manager->get(request);

    QObject::connect(reply, &QNetworkReply::finished, this, [this, reply]() { //wait for response from server
        if (reply->error() == QNetworkReply::NoError) {
            QByteArray response = reply->readAll();
            QJsonDocument doc = QJsonDocument::fromJson(response);
            if (doc.isObject()) {
                QJsonObject obj = doc.object();
                oldSalt = obj["salt"].toString();
                qDebug() << "Salt stored:" << oldSalt;
            }
        } else {
            qDebug() << "Error fetching salt:" << reply->errorString();
        }
        reply->deleteLater();
        reply->manager()->deleteLater();
    });
}
