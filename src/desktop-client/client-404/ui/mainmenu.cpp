#include "mainmenu.h"
#include "ui/ui_mainmenu.h"
#include <qstackedwidget.h>
#include "core/loginsessionmanager.h"

MainMenu::MainMenu(QWidget *parent)
    : BasePage(parent)
    , ui(new Ui::MainMenu)
{
    qDebug() << "Constructing and setting up MainMenu ";
}

void MainMenu::preparePage(){
    qDebug() << "Preparing MainMenu";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
}

void MainMenu::initialisePageUi(){
    this->ui->setupUi(this);
}

void MainMenu::setupConnections(){
    connect(this->ui->uploadButton, &QPushButton::clicked, this, &MainMenu::goToUploadFilePageRequested);
    connect(this->ui->viewFilesButton, &QPushButton::clicked, this, &MainMenu::goToViewFilesPageRequested);
    connect(this->ui->verifyButton, &QPushButton::clicked, this, &MainMenu::goToVerifyPageRequested);
}

void MainMenu::on_logOutButton_clicked() {
    LoginSessionManager::getInstance().clearSession();
    emit this->goToLoginPageRequested();
}

MainMenu::~MainMenu()
{
    qDebug() << "Destroying Main Menu";
    delete this->ui;
}
