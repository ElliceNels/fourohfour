#include "loginpage.h"
#include "pages.h"
#include "password_utils.h"
#include "qjsondocument.h"
#include "qjsonobject.h"
#include "qwidget.h"
#include "ui_loginpage.h"
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
    QString username = this->ui->usernameLineEdit->text();
    QString password = this->ui->passwordLineEdit->text();

    // Check rate limiting
    QString clientIP = getClientIP();
    if (isRateLimited(clientIP)) {
        QMessageBox::warning(this, "Rate Limited", "Too many login attempts. Please try again in 5 minutes.");
        return;
    }
    recordLoginAttempt(clientIP);

    string sUsername = username.toStdString();
    string sPassword = password.toStdString();

    //Debug prints
    cout << "Username: " << sUsername << endl;
    cout << "Password: " << sPassword << endl;

    string hashed;

    hash_password(password.toStdString(), hashed);

    sendCredentials(sUsername, hashed);

    // Debug prints
    cout << "Username: " << username.toStdString() << endl;
    cout << "Password: " << password.toStdString() << endl;

    // Uncomment when we can query password from the server
    // cout << "Password verification: " << verify_password(hashed, secondPassword) << endl;

    // Switch to main menu after login
    emit this->goToMainMenuRequested();
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

void LoginPage::sendCredentials(string name, string password)
{
    QJsonObject json;
    json["username"] = QString::fromStdString(name);
    json["hashed_password"] = QString::fromStdString(password);

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl("http://gobbler.info:4004/login"));
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
