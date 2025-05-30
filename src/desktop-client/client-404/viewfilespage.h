#ifndef VIEWFILESPAGE_H
#define VIEWFILESPAGE_H

#include <QWidget>
#include "basepage.h"

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


private:
    Ui::ViewFilesPage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

    void switchFileListPage(int pageIndex);

signals:
    void goToMainMenuRequested();
};

#endif // VIEWFILESPAGE_H
