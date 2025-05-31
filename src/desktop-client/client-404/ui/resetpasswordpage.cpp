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
#include "constants.h"
#include "loginsessionmanager.h"
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
    QString username = LoginSessionManager::getInstance().getUsername();


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
    if (newPassword.compare(username, Qt::CaseInsensitive) == 0) {
        QMessageBox::warning(this, "Error", "Password cannot be the same as your username.");
        return;
    }
    QString normalizedPassword = newPassword.normalized(QString::NormalizationForm_KC);     // Unicode normalization
    if (newPassword != normalizedPassword) {
        QMessageBox::information(this, "Warning", "Your password contains characters that may look different on other devices.");
    }
    if (dictionaryWords.contains(newPassword.toLower())) {
        QMessageBox::warning(this, "Error", "Password is too common or easily guessable.");
        return;
    }




    if(!getSaltRequest()){
        qDebug() << "Error getting salt";
    }


    QString newSalt = generateSalt(crypto_pwhash_SALTBYTES); //16 bytes


    decryptAndReencryptUserFile(username, oldPassword, oldSalt, newPassword, newSalt);


    sendResetPasswordRequest(newPassword, newSalt);


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


bool ResetPasswordPage::sendResetPasswordRequest(const QString newPassword, const QString newSalt){
    // Set base URL for the server
    LoginSessionManager::getInstance().setBaseUrl(DEFAULT_BASE_URL.c_str());

    // Prepare JSON payload for reset
    QJsonObject requestData;
    requestData["password"] = newPassword;
    requestData["salt"] = newSalt;


    // Make the POST request to the sign_up endpoint
    RequestUtils::Response response = LoginSessionManager::getInstance().post(RESET_PASSWORD_ENDPOINT, requestData);

    // Check if request was successful
    if (response.success) {

        qDebug() << "Reset successful.";
        return true;
    } else {
        QMessageBox::critical(this, "Reset Error",  QString::fromStdString(response.errorMessage));
        return false;
    }
}

bool ResetPasswordPage::getSaltRequest(){
    // Set base URL for the server
    LoginSessionManager::getInstance().setBaseUrl(DEFAULT_BASE_URL.c_str());



    // Make the GET request to the get_current_user endpoint
    RequestUtils::Response response = LoginSessionManager::getInstance().get(GET_USER_ENDPOINT);

    // Check if request was successful
    if (response.success) {
        QJsonObject jsonObj = response.jsonData.object();

        // Extract salt from the response
        oldSalt = jsonObj["salt"].toString();

        return true;
    } else {
        qDebug() << "Error getting salt:" <<response.errorMessage;
        return false;
    }
}

