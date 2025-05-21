#include "registerpage.h"
#include "ui_registerpage.h"
#include <QMessageBox>

RegisterPage::RegisterPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::RegisterPage)
{
    ui->setupUi(this);
    connect(ui->createAccountButton, &QPushButton::clicked, this, &RegisterPage::onCreateAccountClicked);
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

    if (password != confirmPassword) {
        QMessageBox::warning(this, "Error", "Passwords do not match!");
        return;
    }

    // TODO: Add further validation and call your password hashing logic here
    QMessageBox::information(this, "Success", "Account created!");
}
