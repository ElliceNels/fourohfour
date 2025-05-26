#ifndef MAINMENU_H
#define MAINMENU_H

#include <QWidget>

namespace Ui {
class MainMenu;
}

class MainMenu : public QWidget
{
    Q_OBJECT

public:
    explicit MainMenu(QWidget *parent = nullptr);
    ~MainMenu();

private slots:
    void on_uploadButton_clicked();

    void on_verifyButton_clicked();

    void on_logOutButton_clicked();

<<<<<<< HEAD
    void on_resetPasswordButton_clicked();
=======
    void on_viewFilesButton_clicked();
>>>>>>> origin/main

private:
    Ui::MainMenu *ui;
};

#endif // MAINMENU_H
