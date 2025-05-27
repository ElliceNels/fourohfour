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


private:
    Ui::ViewFilesPage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;


signals:
    void goToMainMenuRequested();
};

#endif // VIEWFILESPAGE_H
