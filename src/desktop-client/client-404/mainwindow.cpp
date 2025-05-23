#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "registerpage.h"
#include "titlepage.h"
#include "loginpage.h"
#include "verifypage.h"
#include "pages.h"
#include "constants.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    stackedWidget = new QStackedWidget(this);
    stackedWidget->setStyleSheet(CENTRAL_WIDGET_BACKGROUND);

   
    titlePage = new TitlePage(this);
    registerPage = new RegisterPage(this);
    loginPage = new LoginPage(this);
    verifyPage = new VerifyPage(this);
    uploadFilePage = new UploadFilePage(this);

    stackedWidget->addWidget(titlePage);
    stackedWidget->addWidget(registerPage);
    stackedWidget->addWidget(loginPage);
    stackedWidget->addWidget(verifyPage);
    stackedWidget->addWidget(uploadFilePage);
      
    connect(loginPage, &LoginPage::goToRegisterRequested, this, [this]() {
        stackedWidget->setCurrentIndex(Pages::RegisterPageIndex);
    });

    connect(registerPage, &RegisterPage::goToLoginRequested, this, [this]() {
        stackedWidget->setCurrentIndex(Pages::LoginPageIndex);
    });

    setCentralWidget(stackedWidget);

    stackedWidget->setCurrentIndex(Pages::UploadFilePageIndex); // Show title page

}

MainWindow::~MainWindow()
{
    delete ui;
}
