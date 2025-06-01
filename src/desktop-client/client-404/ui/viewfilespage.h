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

private:
    Ui::ViewFilesPage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

    void switchFileListPage(int pageIndex);
    void displayFiles(const QJsonArray& ownedFiles, const QJsonArray& sharedFiles);
    void addFileItem(const QJsonObject& fileObj, QListWidget* listWidget, const QString& ownerLabel); // Removed isOwner parameter

signals:
    void goToMainMenuRequested();
};

#endif // VIEWFILESPAGE_H
