#include "viewfilespage.h"
#include "ui/ui_viewfilespage.h"
#include <qlistwidget.h>
#include <qstackedwidget.h>
#include "ui/fileitemwidget.h"
#include "ui/frienditemwidget.h" 
#include "constants.h"
#include <QMessageBox>
#include <QJsonObject>
#include <QJsonArray>
#include "core/loginsessionmanager.h"
#include "utils/request_utils.h"
#include "utils/friend_storage_utils.h" 
#include "utils/file_sharing_manager_utils.h" // Add the new utility

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
  
    // Start on the correct pages
    switchMainPage(FILES_LIST_PAGE_INDEX);
    switchFileListPage(OWNED_FILES_PAGE_INDEX);
}

void ViewFilesPage::initialisePageUi(){
    this->ui->setupUi(this);

    ui->ownedFilesListWidget->setAlternatingRowColors(true);
    ui->sharedFilesListWidget->setAlternatingRowColors(true);
}

void ViewFilesPage::setupConnections(){
    connect(this->ui->backButton, &QPushButton::clicked, this, &ViewFilesPage::goToMainMenuRequested);
    connect(this->ui->sharePageBackButton, &QPushButton::clicked, this, &ViewFilesPage::goToFilesListPageRequested);
    connect(this->ui->friendsPageBackButton, &QPushButton::clicked, this, &ViewFilesPage::goToSharingPageRequested);
    connect(this->ui->ownedFilesButton, &QPushButton::clicked, this, &ViewFilesPage::switchToOwnedFilesRequested);
    connect(this->ui->sharedFilesButton, &QPushButton::clicked, this, &ViewFilesPage::switchToSharedFilesRequested);
    connect(this->ui->shareButton, &QPushButton::clicked, this, &ViewFilesPage::goToFriendsPageRequested);
    connect(this, &ViewFilesPage::goToFriendsPageRequested, this, &ViewFilesPage::loadFriendsList);
}

void ViewFilesPage::navigateToFilesListPage() {
    switchMainPage(FILES_LIST_PAGE_INDEX);
}

void ViewFilesPage::navigateToSharingPage() {
    switchMainPage(SHARING_PAGE_INDEX);
}

void ViewFilesPage::navigateToFriendsPage() {
    switchMainPage(FRIENDS_LIST_PAGE_INDEX);
    loadFriendsList(); 
}

void ViewFilesPage::switchToOwnedFiles() {
    switchFileListPage(OWNED_FILES_PAGE_INDEX);
}

void ViewFilesPage::switchToSharedFiles() {
    switchFileListPage(SHARED_FILES_PAGE_INDEX);
}

void ViewFilesPage::switchMainPage(int pageIndex) {
    ui->mainStackedWidget->setCurrentIndex(pageIndex);
}

void ViewFilesPage::onShareRequested() {
    // Check if a file is selected
    if (selectedFileUuid.isEmpty()) {
        QMessageBox::warning(this, "Selection Required", "Please select a file to share first.");
        return;
    }
    
    // Switch to the sharing page
    switchMainPage(SHARING_PAGE_INDEX);
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
    
    // Connect to file widget signals 
    connect(fileWidget, &FileItemWidget::fileDeleted, this, &ViewFilesPage::fetchUserFiles);
    connect(fileWidget, &FileItemWidget::shareRequested, [this, fileUuid]() {
        this->onFileSelected(fileUuid);
        this->onShareRequested();
    });
    
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

void ViewFilesPage::loadFriendsList() {
    // Clear existing items in the list widget
    ui->friendsListWidget->clear();
    
    // Get all friends except self
    QMap<QString, QString> friends = FriendStorageUtils::getAllFriendsExceptSelf(this);
    
    if (friends.isEmpty()) {
        // If no friends found, add a message item
        QListWidgetItem* emptyItem = new QListWidgetItem("No friends found. Add friends using the verify page.", ui->friendsListWidget);
        emptyItem->setTextAlignment(Qt::AlignCenter);
        return;
    }
    
    // Iterate through the map of friends
    for (auto it = friends.constBegin(); it != friends.constEnd(); ++it) {
        addFriendItem(it.key(), it.value());
    }
}


void ViewFilesPage::addFriendItem(const QString &username, const QString &publicKey) {
    // Create the friend item widget
    FriendItemWidget* friendWidget = new FriendItemWidget(username, publicKey, this);
    
    // Connect the signals
    connect(friendWidget, &FriendItemWidget::shareRequested, this, &ViewFilesPage::onFriendShareRequested);
    connect(friendWidget, &FriendItemWidget::deleteRequested, this, &ViewFilesPage::onFriendDeleteRequested);
    
    // Create a list item and add to the list widget
    QListWidgetItem* item = new QListWidgetItem(ui->friendsListWidget);
    ui->friendsListWidget->setItemWidget(item, friendWidget);
    
    // Set the size hint to ensure proper display
    item->setSizeHint(friendWidget->sizeHint());
}

void ViewFilesPage::onFriendShareRequested(const QString &username) {
    qDebug() << "Share requested for friend:" << username;
    
    // Check if a file is selected
    if (selectedFileUuid.isEmpty()) {
        QMessageBox::warning(this, "Selection Required", "Please select a file to share first.");
        return;
    }
    
    // Get the recipient's public key - fixed method name here
    QString publicKey = FriendStorageUtils::getUserPublicKey(username, this);
    if (publicKey.isEmpty()) {
        QMessageBox::warning(this, "Error", "Could not retrieve public key for " + username);
        return;
    }
    
    // Show a confirmation dialog
    if (!UIUtils::confirmAction("Confirm Sharing", 
                              QString("Are you sure you want to share this file with %1?").arg(username), 
                              this)) {
        return;
    }
    
    // Use FileSharingManagerUtils to share the file
    bool success = FileSharingManagerUtils::shareFileWithUser(
        selectedFileUuid,
        username,
        publicKey,
        this
    );
    
    if (success) {
        QMessageBox::information(this, "Success", 
                               QString("File shared successfully with %1.").arg(username));
        // Return to files page after successful sharing
        navigateToFilesListPage();
    }
    // Error handling is done within the FileSharingManagerUtils class
}
void ViewFilesPage::onFriendDeleteRequested(const QString &username) {
    if (FriendStorageUtils::removeFriend(username, this)) {
        QMessageBox::information(this, "Success", "Friend removed successfully.");
        loadFriendsList(); // Reload the friends list to reflect changes
    } else {
        QMessageBox::warning(this, "Error", "Failed to remove friend.");
    }
}

ViewFilesPage::~ViewFilesPage()
{
    qDebug() << "Destroying View Files Page";
    delete this->ui;
}

