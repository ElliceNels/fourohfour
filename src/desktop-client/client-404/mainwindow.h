#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include "loginpage.h"
#include "registerpage.h"
#include "titlepage.h"
#include "verifypage.h"
#include "uploadfilepage.h"
#include <QFile>
#include <QTextStream>
#include <QFileDialog>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

private:
    Ui::MainWindow *ui;
    QStackedWidget *stackedWidget;
    TitlePage *titlePage;
    RegisterPage *registerPage;
    LoginPage *loginPage;
    VerifyPage *verifyPage;
    UploadFilePage *uploadFilePage;
};

#endif // MAINWINDOW_H
