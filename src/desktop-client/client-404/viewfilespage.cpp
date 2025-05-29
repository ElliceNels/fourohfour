#include "viewfilespage.h"
#include "ui_viewfilespage.h"
#include <qstackedwidget.h>
#include "fileitemwidget.h"

ViewFilesPage::ViewFilesPage(QWidget *parent)
    : BasePage(parent)
    , ui(new Ui::ViewFilesPage)
{
    qDebug() << "Constructing and setting up View Files Page";
}
void ViewFilesPage::preparePage(){
    qDebug() << "Preparing View Files Page";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
}

void ViewFilesPage::initialisePageUi(){
    this->ui->setupUi(this);
}

void ViewFilesPage::setupConnections(){
    connect(this->ui->backButton, &QPushButton::clicked, this, &ViewFilesPage::goToMainMenuRequested);
}

ViewFilesPage::~ViewFilesPage()
{
    qDebug() << "Destroying View Files Page";
    delete this->ui;
}

