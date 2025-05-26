#include "titlepage.h"
#include "ui_titlepage.h"
#include <QStackedWidget>

TitlePage::TitlePage(QWidget *parent)
    : BasePage(parent)
    , ui(new Ui::TitlePage)
{
    qDebug() << "Constructing and setting up Title Page";
    // initialisePageUi();
    // setupConnections();

}
void TitlePage::preparePage(){
    qDebug() << "Preparing Title Page";
    initialisePageUi();    // Will call the derived class implementation
    setupConnections();    // Will call the derived class implementation
}

void TitlePage::initialisePageUi(){
    qDebug() << "Title Page initialisePageUi";
    ui->setupUi(this);
}

void TitlePage::setupConnections(){
    connect(ui->signupButton, &QPushButton::clicked, this, &TitlePage::goToRegisterRequested);
    connect(ui->loginButton, &QPushButton::clicked, this, &TitlePage::goToLoginRequested);
}

TitlePage::~TitlePage()
{
    qDebug() << "Destroying Title Page";
    delete ui;
}


