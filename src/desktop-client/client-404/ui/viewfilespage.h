#ifndef VIEWFILESPAGE_H
#define VIEWFILESPAGE_H

#include <QWidget>
#include <QListWidget> 
#include <QJsonArray>   
#include <QJsonObject> 
#include "ui/basepage.h"

namespace Ui {
class ViewFilesPage;
}

class ViewFilesPage : public BasePage
{
    Q_OBJECT

public:
    explicit ViewFilesPage(QWidget *parent = nullptr);
    void preparePage() override;
    ~ViewFilesPage();
    ViewFilesPage& operator=(const ViewFilesPage&) = delete;  // Prevent assignment

public slots:
    void fetchUserFiles();
    void switchMainPage(int pageIndex); // New method to switch between main pages
    void onShareRequested(); // New slot to handle share requests
    void navigateToFilesListPage();
    void navigateToSharingPage();
    void navigateToFriendsPage();
    void switchToOwnedFiles();
    void switchToSharedFiles();
    void loadFriendsList();
    void onFriendShareRequested(const QString &username);
    void onFriendDeleteRequested(const QString &username);

private:
    Ui::ViewFilesPage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

    void switchFileListPage(int pageIndex);
    void displayFiles(const QJsonArray& ownedFiles, const QJsonArray& sharedFiles);
    void addFileItem(const QJsonObject& fileObj, QListWidget* listWidget, const QString& ownerLabel); 
    void addFriendItem(const QString &username, const QString &publicKey);

signals:
    void goToMainMenuRequested();
    void goToFilesListPageRequested();
    void goToSharingPageRequested();
    void goToFriendsPageRequested();
    void switchToOwnedFilesRequested();
    void switchToSharedFilesRequested();
};

#endif // VIEWFILESPAGE_H
