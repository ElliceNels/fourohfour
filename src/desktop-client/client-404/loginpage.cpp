#include "loginpage.h"
#include "qwidget.h"
#include "ui_loginpage.h"
#include <iostream>
#include <qstackedwidget.h>
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

LoginPage::~LoginPage()
{
    qDebug() << "Destroying Login Page";
    delete this->ui;
}
