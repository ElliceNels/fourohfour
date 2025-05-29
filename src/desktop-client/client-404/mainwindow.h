#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include "loginpage.h"
#include "registerpage.h"
#include "titlepage.h"
#include "verifypage.h"
#include "uploadfilepage.h"
#include "mainmenu.h"
#include "viewfilespage.h"
#include <QFile>
#include <QTextStream>
#include <QFileDialog>
#include <QMessageBox>

inline QStackedWidget& operator+(QStackedWidget& stack, QWidget* widget) {
    stack.addWidget(widget);
    return stack;
}

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
    MainMenu *mainMenu;
    ViewFilesPage *viewFilesPage;

    // Templates must be fully defined in the header file because
    // the compiler needs to see the complete definition wherever
    // the template is instantiated.

    template<typename PageType>
    PageType* createAndAddPage(QWidget* parent, QStackedWidget* stackedWidget) {
        BasePage* basePage = new PageType(parent);   // Runtime polymorphism
        basePage->preparePage();                     // Calls overridden preparePage()
        stackedWidget->addWidget(basePage);
        return static_cast<PageType*>(basePage);     // Cast to actual type
    }

    template<typename SenderType, typename SignalFunc>
    void connectPageNavigation(SenderType* sender, SignalFunc signal, int pageIndex) {
        connect(sender, signal, this, [this, pageIndex]() {
            stackedWidget->setCurrentIndex(pageIndex);
        });
    }
};

#endif // MAINWINDOW_H
