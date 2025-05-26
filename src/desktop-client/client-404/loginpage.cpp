#include "loginpage.h"
#include "pages.h"
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
    // initialisePageUi();
    // setupConnections();
}

void LoginPage::preparePage(){
    qDebug() << "Preparing Login Page";
    initialisePageUi();    // Will call the derived class implementation
    setupConnections();    // Will call the derived class implementation
}

void LoginPage::initialisePageUi(){
    qDebug() << "Login Page initialisePageUi";
    ui->setupUi(this);
    ui->passwordLineEdit->setEchoMode(QLineEdit::Password);
}

void LoginPage::setupConnections(){

    // Connect the button click to the slot
    connect(ui->loginButton, &QPushButton::clicked, this, &LoginPage::onLoginButtonClicked);
    connect(ui->goToRegisterButton, &QPushButton::clicked, this, &LoginPage::goToRegisterRequested);
    connect(ui->showPasswordButton, &QPushButton::clicked, this, &LoginPage::onShowPasswordClicked);
}

void LoginPage::onLoginButtonClicked()
{
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();

    //Debug prints
    cout << "Username: " << username.toStdString() << endl;
    cout << "Password: " << password.toStdString() << endl;

    //Uncomment when we can query password from the server
    //cout << "Password verification: " << verify_password(hashed, secondPassword) << endl;

    // Switch to main menu after login
    emit goToMainMenuRequested();
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

LoginPage::~LoginPage()
{
    qDebug() << "Destroying Login Page";
    delete ui;
}
