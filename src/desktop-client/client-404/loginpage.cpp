#include "loginpage.h"
#include "qwidget.h"
#include "ui_loginpage.h"
#include <iostream>
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

    //Debug prints
    cout << "Username: " << username.toStdString() << endl;
    cout << "Password: " << password.toStdString() << endl;

    //Uncomment when we can query password from the server
    //cout << "Password verification: " << verify_password(hashed, secondPassword) << endl;
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
