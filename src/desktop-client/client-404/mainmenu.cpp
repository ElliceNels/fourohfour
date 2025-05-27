#include "mainmenu.h"
#include "ui_mainmenu.h"
#include <qstackedwidget.h>
#include "loginsessionmanager.h"

MainMenu::MainMenu(QWidget *parent)
    : BasePage(parent)
    , ui(new Ui::MainMenu)
{

    qDebug() << "Constructing and setting up MainMenu ";
}

void MainMenu::preparePage(){
    qDebug() << "Preparing MainMenu";
    initialisePageUi();    // Will call the derived class implementation
    setupConnections();    // Will call the derived class implementation
}


void MainMenu::initialisePageUi(){
    ui->setupUi(this);
}

void MainMenu::setupConnections(){
    connect(ui->uploadButton, &QPushButton::clicked, this, &MainMenu::goToUploadFilePageRequested);
    connect(ui->viewFilesButton, &QPushButton::clicked, this, &MainMenu::goToViewFilesPageRequested);
    connect(ui->verifyButton, &QPushButton::clicked, this, &MainMenu::goToVerifyPageRequested);
}


void MainMenu::on_logOutButton_clicked() {
    LoginSessionManager::getInstance().clearSession();
    emit goToLoginPageRequested();
}

MainMenu::~MainMenu()
{
    qDebug() << "Destroying Main Menu";
    delete ui;
}

