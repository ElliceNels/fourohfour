#include "viewfilespage.h"
#include "ui/ui_viewfilespage.h"
#include <qlistwidget.h>
#include <qstackedwidget.h>
#include "ui/fileitemwidget.h"
#include "constants.h"
#include <QMessageBox>
#include <QJsonObject>
#include <QJsonArray>
#include "core/loginsessionmanager.h"
#include "utils/request_utils.h"

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

/**
 * @brief Fetches the user's files from the server
 * 
 * Makes a GET request to the server API to retrieve the user's owned and shared files,
 * then displays them in the appropriate list widgets.
 */
void ViewFilesPage::fetchUserFiles() {
    qDebug() << "Fetching user files from server";
    
    // Make the GET request to the files endpoint
    RequestUtils::Response response = LoginSessionManager::getInstance().get(GET_USER_FILES_ENDPOINT);
    
    // Check if request was successful
    if (response.success) {
        QJsonObject jsonObj = response.jsonData.object();
        QJsonArray ownedFiles = jsonObj["owned_files"].toArray();
        QJsonArray sharedFiles = jsonObj["shared_files"].toArray();
        
        qDebug() << "Received" << ownedFiles.size() << "owned files and" << sharedFiles.size() << "shared files";
        
        // Display files in UI
        displayFiles(ownedFiles, sharedFiles);
    } else {
        QMessageBox::critical(this, "Error", QString::fromStdString("Failed to fetch files: " + response.errorMessage));
    }
}

/**
 * @brief Helper method to create and add a file item widget to a list
 * 
 * @param fileObj JSON object containing file metadata
 * @param listWidget The list widget to add the file to
 * @param ownerLabel Text to display in the owner field
 */
void ViewFilesPage::addFileItem(const QJsonObject& fileObj, QListWidget* listWidget, const QString& ownerLabel) {
    
    // parse file size from string to qint64
    qint64 fileSize = 0;
    QString fileSizeStr = fileObj["file_size"].toString();
    if (!fileSizeStr.isEmpty()) {
        fileSize = static_cast<qint64>(fileSizeStr.toDouble());
    }
    
    // Create file item widget and add to list
    FileItemWidget* fileWidget = new FileItemWidget(
        fileObj["filename"].toString(),
        fileObj["format"].toString(),
        fileSize,
        ownerLabel,
        fileObj["is_owner"].toBool(false),
        fileObj["uuid"].toString(),
        this
    );
    
    // Connect to the  fileDeleted signal to refresh the file list
    connect(fileWidget, &FileItemWidget::fileDeleted, this, &ViewFilesPage::fetchUserFiles);
    
    QListWidgetItem* item = new QListWidgetItem(listWidget);
    listWidget->setItemWidget(item, fileWidget);
    item->setSizeHint(fileWidget->sizeHint());
}

/**
 * @brief Displays files in the appropriate list widgets
 * 
 * @param ownedFiles JSON array of files owned by the user
 * @param sharedFiles JSON array of files shared with the user
 */
void ViewFilesPage::displayFiles(const QJsonArray& ownedFiles, const QJsonArray& sharedFiles) {
    // Clear existing items
    ui->ownedFilesListWidget->clear();
    ui->sharedFilesListWidget->clear();
    
    // Add owned files
    for (const QJsonValue& fileValue : ownedFiles) {
        addFileItem(
            fileValue.toObject(), 
            ui->ownedFilesListWidget,
            "You" // Owner label
        );
    }
    
    // Add shared files
    for (const QJsonValue& fileValue : sharedFiles) {
        addFileItem(
            fileValue.toObject(), 
            ui->sharedFilesListWidget,
            "Not you lol" // Owner label
        );
    }
}

ViewFilesPage::~ViewFilesPage()
{
    qDebug() << "Destroying View Files Page";
    delete this->ui;
}

