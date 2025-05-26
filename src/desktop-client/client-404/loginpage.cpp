#include "loginpage.h"
#include "pages.h"
#include "password_utils.h"
#include "qjsondocument.h"
#include "qjsonobject.h"
#include "qwidget.h"
#include "ui_loginpage.h"
#include <iostream>
#include <qstackedwidget.h>
#include "pages.h"
#include <QMessageBox>
#include "password_utils.h"
#include <iostream>
#include <QJsonObject>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <qstackedwidget.h>
using namespace std;

LoginPage::LoginPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::LoginPage)
{
    ui->setupUi(this);

    // Connect the button click to the slot
    connect(ui->loginButton, &QPushButton::clicked, this, &LoginPage::onLoginButtonClicked);
    connect(ui->goToRegisterButton, &QPushButton::clicked, this, &LoginPage::goToRegisterRequested);

    ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
    connect(ui->showPasswordButton, &QPushButton::clicked, this, &LoginPage::onShowPasswordClicked);
}

LoginPage::~LoginPage()
{
    delete ui;
}

void LoginPage::onLoginButtonClicked()
{
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();

    string sUsername = username.toStdString();
    string sPassword = password.toStdString();

    //Debug prints
    cout << "Username: " << sUsername << endl;
    cout << "Password: " << sPassword << endl;

    string hashed;

    hash_password(password.toStdString(), hashed);

    sendCredentials(sUsername, sPassword);

    // Switch to main menu after login
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(Pages::MainMenuIndex);
    }
}

void LoginPage::onShowPasswordClicked()
{
    if (ui->passwordLineEdit->echoMode() == QLineEdit::Password) {
        ui->passwordLineEdit->setEchoMode(QLineEdit::Normal);
        ui->showPasswordButton->setText("Hide");
    } else {
        ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
        ui->showPasswordButton->setText("Show");
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
