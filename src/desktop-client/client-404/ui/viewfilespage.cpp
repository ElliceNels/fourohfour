#include "viewfilespage.h"
#include "ui/ui_viewfilespage.h"
#include <qlistwidget.h>
#include <qstackedwidget.h>
#include "ui/fileitemwidget.h"
#include "constants.h"

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

    ui->ownedFilesListWidget->setAlternatingRowColors(true);
    ui->sharedFilesListWidget->setAlternatingRowColors(true);
}

void ViewFilesPage::setupConnections(){
    connect(this->ui->backButton, &QPushButton::clicked, this, &ViewFilesPage::goToMainMenuRequested);
    connect(this->ui->ownedFilesButton, &QPushButton::clicked, this, [this]() { switchFileListPage(OWNED_FILES_PAGE_INDEX); });
    connect(this->ui->sharedFilesButton, &QPushButton::clicked, this, [this]() { switchFileListPage(SHARED_FILES_PAGE_INDEX); });
}

void ViewFilesPage::switchFileListPage(int pageIndex) {
    ui->fileListStackedWidget->setCurrentIndex(pageIndex);
    
    if (pageIndex == OWNED_FILES_PAGE_INDEX) {
        ui->viewFilesLabel->setText("Owned by me");
        ui->ownedFilesButton->setStyleSheet(Styles::SelectedSidebarButton);
        ui->sharedFilesButton->setStyleSheet(Styles::UnselectedSidebarButton);
    } else if (pageIndex == SHARED_FILES_PAGE_INDEX) {
        ui->viewFilesLabel->setText("Shared with me");
        ui->sharedFilesButton->setStyleSheet(Styles::SelectedSidebarButton);
        ui->ownedFilesButton->setStyleSheet(Styles::UnselectedSidebarButton);
    }
}
ViewFilesPage::~ViewFilesPage()
{
    qDebug() << "Destroying View Files Page";
    delete this->ui;
}

