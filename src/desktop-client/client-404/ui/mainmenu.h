#ifndef MAINMENU_H
#define MAINMENU_H

#include <QWidget>
#include "ui/basepage.h"

namespace Ui {
class MainMenu;
}

class MainMenu : public BasePage
{
    Q_OBJECT

public:
    explicit MainMenu(QWidget *parent = nullptr);
    void preparePage() override;
    ~MainMenu();
    MainMenu& operator=(const MainMenu&) = delete;  // Prevent assignment

private slots:
    void on_logOutButton_clicked();


private:
    Ui::MainMenu *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToUploadFilePageRequested();
    void goToVerifyPageRequested();
    void goToLoginPageRequested();
    void goToViewFilesPageRequested();
    void goToResetPasswordRequested();

};

#endif // MAINMENU_H
