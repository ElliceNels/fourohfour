#include "ui/loginpage.h"
#include <qwidget.h>
#include "ui/ui_loginpage.h"
#include <iostream>
#include <qstackedwidget.h>
#include <QMessageBox>
#include "password_utils.h"
#include <iostream>
#include <QJsonObject>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <qstackedwidget.h>
#include <QHostInfo>
#include "constants.h"
#include "loginsessionmanager.h"
#include "key_utils.h"
#include "utils/x3dh_network_utils.h"
#include "utils/file_sharing_utils.h"
#include "friend_storage_utils.h"
#include "utils/file_crypto_utils.h"
using namespace std;

LoginPage::LoginPage(QWidget *parent) :
    BasePage(parent),
    ui(new Ui::LoginPage)
{
    qDebug() << "Constructing and setting up Login Page";
}

void LoginPage::preparePage(){
    qDebug() << "Preparing Login Page";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
    this->ui->loginButton->setEnabled(true);
    this->ui->loginButton->setText("Log In");
    this->ui->loginButton->repaint();
}

void LoginPage::initialisePageUi(){
    this->ui->setupUi(this);
    this->ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
}

void LoginPage::setupConnections(){
    connect(this->ui->loginButton, &QPushButton::clicked, this, &LoginPage::onLoginButtonClicked);
    connect(this->ui->goToRegisterButton, &QPushButton::clicked, this, &LoginPage::goToRegisterRequested);
    connect(this->ui->showPasswordButton, &QPushButton::clicked, this, &LoginPage::onShowPasswordClicked);
}

void LoginPage::onLoginButtonClicked()
{
    // Disable button and change text at the start
    this->ui->loginButton->setEnabled(false);
    this->ui->loginButton->setText("Logging in...");
    this->ui->loginButton->repaint();

    QString username = this->ui->usernameLineEdit->text();
    QString password = this->ui->passwordLineEdit->text();

    // Check rate limiting
    QString clientIP = getClientIP();
    if (isRateLimited(clientIP)) {
        QMessageBox::warning(this, "Rate Limited", "Too many login attempts. Please try again in 5 minutes.");
        this->ui->loginButton->setEnabled(true);
        this->ui->loginButton->setText("Log In");
        this->ui->loginButton->repaint();
        return;
    }
    recordLoginAttempt(clientIP);

    string sUsername = username.toStdString();
    string sPassword = password.toStdString();

    LoginSessionManager::getInstance().setUsername(username);
    LoginSessionManager::getInstance().setBaseUrl(DEFAULT_BASE_URL.c_str());

    if (sendLogInRequest(username, password)) {
        // Get salt for key derivation
        QString salt = getSaltRequest();

        if (decryptMasterKey(username, password, salt)) {
            // Switch to main menu after login
            this->ui->usernameLineEdit->clear();
            this->ui->passwordLineEdit->clear();
            this->ui->loginButton->setEnabled(true);
            this->ui->loginButton->setText("Log In");
            this->ui->loginButton->repaint();
            emit this->goToMainMenuRequested();
        } else {
            // Only reset the button if login failed
            this->ui->loginButton->setEnabled(true);
            this->ui->loginButton->setText("Log In");
            this->ui->loginButton->repaint();
        }
    } else {
        // Only reset the button if login failed
        this->ui->loginButton->setEnabled(true);
        this->ui->loginButton->setText("Log In");
        this->ui->loginButton->repaint();
    }
}

bool LoginPage::sendLogInRequest(const QString& username, const QString& password)
{
    // Prepare JSON payload for registration
    QJsonObject requestData;
    requestData["username"] = username;
    requestData["password"] = password;

    // Make the POST request to the sign_up endpoint
    RequestUtils::Response response = LoginSessionManager::getInstance().post(LOGIN_ENDPOINT, requestData);

    // Check if request was successful
    if (response.success) {
        QJsonObject jsonObj = response.jsonData.object();

        // Extract tokens from the response
        QString accessToken = jsonObj["access_token"].toString();
        QString refreshToken = jsonObj["refresh_token"].toString();
        
        // Extract key status information
        bool otpkCountLow = jsonObj["otpk_count_low"].toBool();
        bool spk_outdated = jsonObj["spk_outdated"].toBool();
        int unusedOtpkCount = jsonObj["unused_otpk_count"].toInt();

        // Set tokens in the LoginSessionManager
        LoginSessionManager::getInstance().setTokens(accessToken, refreshToken);
        
        // Handle low OTPK count
        if (otpkCountLow) {
            qDebug() << "OTPK count is low (" << unusedOtpkCount << "). Generating new OTPKs...";
            QJsonArray newOTPKs = FileSharingUtils::generateOneTimePreKeyPairs();
            if (!newOTPKs.isEmpty()) {
                if (X3DHNetworkUtils::uploadOneTimePreKeys(newOTPKs, this)) {
                    qDebug() << "Successfully uploaded" << newOTPKs.size() << "new one-time pre-keys";
                } else {
                    qDebug() << "Failed to upload new one-time pre-keys";
                }
            }
        } else if (!otpkCountLow) {
            qDebug() << "OTPK count is sufficient (" << unusedOtpkCount << "). No action needed.";
        }

        if (spk_outdated) {
            qDebug() << "SPK is outdated. Generating new signed pre-key...";
            QString signedPreKeyPublic, signedPreKeyPrivate, signature;
            if (replaceSignedPreKey(username, signedPreKeyPublic, signature)) {
                // Save the new signed pre-key
                if (X3DHNetworkUtils::updateSignedPreKey(signedPreKeyPublic, signature, this)) {
                    qDebug() << "Successfully updated signed pre-key";
                } else {
                    qDebug() << "Failed to update signed pre-key on server";
                }
            } else {
                qDebug() << "Failed to generate new signed pre-key";
            }
        } else if (!spk_outdated) {
            qDebug() << "SPK is up-to-date. No action needed.";
        }

        qDebug() << "Login successful. Tokens saved in session manager.";
        return true;
    } else {
        QMessageBox::critical(this, "Login Error", "Invalid username or password!");
        return false;
    }
}

void LoginPage::onShowPasswordClicked()
{
    if (this->ui->passwordLineEdit->echoMode() == QLineEdit::Password) {
        this->ui->passwordLineEdit->setEchoMode(QLineEdit::Normal);
        this->ui->showPasswordButton->setText("Hide");
    } else {
        this->ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
        this->ui->showPasswordButton->setText("Show");
    }
}

bool LoginPage::replaceSignedPreKey(const QString username, QString& signedPreKeyPublic, QString& signature){
    QString signedPreKeyPrivate;
    QString identityPublicKeyBase64, identityPrivateKeyBase64;

    identityPublicKeyBase64 = FriendStorageUtils::getUserPublicKey(username, this);

    if (identityPublicKeyBase64.isEmpty()) {
        qDebug() << "Failed to retrieve identity public key for user:" << username;
        return false;
    }

    // Get the master key for accessing encrypted storage
    const SecureVector masterKey = LoginSessionManager::getInstance().getMasterKey();
    if (!FileCryptoUtils::validateMasterKey(masterKey)) {
        qDebug() << "Invalid master key for accessing identity private key";
        return false;
    }

    // Read encrypted key storage file
    QString filepath = FileCryptoUtils::buildKeyStorageFilePath();
    QByteArray jsonData;
    if (!FileCryptoUtils::readAndDecryptKeyStorage(filepath, masterKey, jsonData)) {
        qDebug() << "Failed to decrypt key storage for user:" << username;
        return false;
    }

    // Parse JSON data to extract private key
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        qDebug() << "Failed to parse key storage JSON:" << parseError.errorString();
        return false;
    }

    QJsonObject rootObject = doc.object();
    if (!rootObject.contains("privateKey") || !rootObject["privateKey"].isString()) {
        qDebug() << "Identity private key not found in key storage";
        return false;
    }

    // Extract the identity private key
    identityPrivateKeyBase64 = rootObject["privateKey"].toString();
    
    // Generate new signed prekey and signature using the identity keys
    if (!FileSharingUtils::generateSignedPreKey(
            identityPublicKeyBase64, 
            identityPrivateKeyBase64, 
            signedPreKeyPublic, 
            signedPreKeyPrivate, 
            signature)) {
        qDebug() << "Failed to generate signed prekey";
        return false;
    }
    
    qDebug() << "Successfully generated new signed prekey for user:" << username;
    return true;
}

QString LoginPage::getSaltRequest(){

    // Make the GET request to the get_current_user endpoint
    RequestUtils::Response response = LoginSessionManager::getInstance().get(GET_USER_ENDPOINT);

    // Check if request was successful
    if (response.success) {
        QJsonObject jsonObj = response.jsonData.object();

        // Extract salt from the response
        QString oldSalt = jsonObj["salt"].toString();
        QByteArray decodedSalt = QByteArray::fromBase64(oldSalt.toUtf8());
        oldSalt = QString::fromUtf8(decodedSalt);  // Convert back to QString


        return oldSalt;
    } else {
        qDebug() << "Error getting salt:" <<response.errorMessage;
        return NULL;
    }
}

bool LoginPage::isRateLimited(const QString& ip)
{
    if (!loginAttempts.contains(ip)) {
        return false;
    }

    QList<QDateTime>& attempts = loginAttempts[ip];
    QDateTime now = QDateTime::currentDateTime();

    QDateTime* startPtr = attempts.data(); //relationship between arrays and pointers
    QDateTime* endPtr = startPtr + attempts.size();
    QDateTime* currentPtr = startPtr;

    // Move startPtr forward for each old element we want to discard using pointer arithmetic
    while (currentPtr < endPtr) {
        if (currentPtr->msecsTo(now) > RATE_LIMIT_WINDOW_MS) {
            //Old attempt, move startPtr forward
            startPtr++;
        }
        currentPtr++;
    }

    // Resize the list to only keep elements from startPtr onwards
    attempts.resize(endPtr - startPtr);

    // Debug print
    cout << "attempts size:" << attempts.size() << endl;

    return attempts.size() >= MAX_LOGIN_ATTEMPTS;
}
void LoginPage::recordLoginAttempt(const QString& ip)
{
    if (!loginAttempts.contains(ip)) {
        loginAttempts[ip] = QList<QDateTime>();
    }
    loginAttempts[ip].append(QDateTime::currentDateTime());
    cout << "made attempt record" << endl;
}

QString LoginPage::getClientIP()
{
    cout << "returned hostname" << endl;
    return QHostInfo::localHostName();
}

LoginPage::~LoginPage()
{
    qDebug() << "Destroying Login Page";
    delete this->ui;

}
