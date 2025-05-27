#include "titlepage.h"
#include "ui_titlepage.h"
#include <QStackedWidget>

TitlePage::TitlePage(QWidget *parent)
    : BasePage(parent)
    ,ui(new Ui::TitlePage)
{
    qDebug() << "Constructing and setting up Title Page";

}
void TitlePage::preparePage(){
    qDebug() << "Preparing Title Page";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
}

void TitlePage::initialisePageUi(){
    this->ui->setupUi(this);
}

void TitlePage::setupConnections(){
    connect(this->ui->signupButton, &QPushButton::clicked, this, &TitlePage::goToRegisterRequested);
    connect(this->ui->loginButton, &QPushButton::clicked, this, &TitlePage::goToLoginRequested);
}

TitlePage::~TitlePage()
{
    qDebug() << "Destroying Title Page";
    delete this->ui;
}


