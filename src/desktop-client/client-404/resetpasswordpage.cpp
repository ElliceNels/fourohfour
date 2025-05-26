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
using namespace std;

ResetPasswordPage::ResetPasswordPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ResetPasswordPage)
{
    ui->setupUi(this);

    ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
    ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);

    connect(ui->updatePasswordButton, &QPushButton::clicked, this, &::ResetPasswordPage::onUpdatePasswordClicked);
    connect(ui->showPasswordButton, &QPushButton::clicked, this, &ResetPasswordPage::onShowPasswordClicked);
}

ResetPasswordPage::~ResetPasswordPage()
{
    delete ui;
}

void ResetPasswordPage::onUpdatePasswordClicked()
{
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
    if (password.trimmed().isEmpty()) {
        QMessageBox::warning(this, "Error", "Password cannot be empty or only spaces.");
        return;
    }
    // if (password.compare(accountName, Qt::CaseInsensitive) == 0) {
    //     QMessageBox::warning(this, "Error", "Password cannot be the same as your username.");
    //     return;
    // }
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






    QString salt = generateSalt(crypto_pwhash_SALTBYTES); //16 bytes
    QByteArray saltRaw = QByteArray::fromBase64(salt.toUtf8()); // decode to raw bytes
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    string sPassword = password.toStdString();


    deriveKeyFromPassword(sPassword, reinterpret_cast<const unsigned char*>(saltRaw.constData()), key, sizeof(key));


    //Debug prints
    cout << hashed << endl;


    //Uncomment when server side is ready
    //sendCredentials(sAccountName, sEmail, hashed, pubKey, sSalt);


    QMessageBox::information(this, "Success", "Account created!");


    // Switch to main menu after registration
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
        ui->showPasswordButton->setText("Hide");
    } else {
        ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
        ui->confirmPasswordLineEdit->setEchoMode(QLineEdit::Password);
        ui->showPasswordButton->setText("Show");
    }
}

void ResetPasswordPage::sendCredentials(string password)
{
    QJsonObject json;
    json["hashedPassword"] = QString::fromStdString(password);

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl("https://gobbler.info"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = manager->post(request, jsonData);
}
