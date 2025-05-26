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
    stackedWidget->setStyleSheet(Styles::CentralWidget);


    titlePage = createAndAddPage<TitlePage>(this, stackedWidget);
    registerPage = createAndAddPage<RegisterPage>(this, stackedWidget);
    loginPage = createAndAddPage<LoginPage>(this, stackedWidget);
    verifyPage = createAndAddPage<VerifyPage>(this, stackedWidget);
    uploadFilePage = createAndAddPage<UploadFilePage>(this, stackedWidget);
    mainMenu = createAndAddPage<MainMenu>(this, stackedWidget);
    viewFilesPage = createAndAddPage<ViewFilesPage>(this, stackedWidget);

    stackedWidget->addWidget(titlePage);
    stackedWidget->addWidget(registerPage);
    stackedWidget->addWidget(loginPage);
    stackedWidget->addWidget(verifyPage);
    stackedWidget->addWidget(uploadFilePage);
    stackedWidget->addWidget(mainMenu);
    stackedWidget->addWidget(viewFilesPage);

    // Title page navigation
    connectPageNavigation(titlePage, &TitlePage::goToRegisterRequested, Pages::RegisterPageIndex);
    connectPageNavigation(titlePage, &TitlePage::goToLoginRequested, Pages::LoginPageIndex);

    // Login/Register navigation
    connectPageNavigation(loginPage, &LoginPage::goToRegisterRequested, Pages::RegisterPageIndex);
    connectPageNavigation(registerPage, &RegisterPage::goToLoginRequested, Pages::LoginPageIndex);

    // Back to main menu navigation
    connectPageNavigation(verifyPage, &VerifyPage::goToMainMenuRequested, Pages::MainMenuIndex);
    connectPageNavigation(uploadFilePage, &UploadFilePage::goToMainMenuRequested, Pages::MainMenuIndex);
    connectPageNavigation(viewFilesPage, &ViewFilesPage::goToMainMenuRequested, Pages::MainMenuIndex);
    connectPageNavigation(loginPage, &LoginPage::goToMainMenuRequested, Pages::MainMenuIndex);
    connectPageNavigation(registerPage, &RegisterPage::goToMainMenuRequested, Pages::MainMenuIndex);


    // Main menu navigation
    connectPageNavigation(mainMenu, &MainMenu::goToUploadFilePageRequested, Pages::UploadFilePageIndex);
    connectPageNavigation(mainMenu, &MainMenu::goToVerifyPageRequested, Pages::VerifyPageIndex);
    connectPageNavigation(mainMenu, &MainMenu::goToLoginPageRequested, Pages::LoginPageIndex);
    connectPageNavigation(mainMenu, &MainMenu::goToViewFilesPageRequested, Pages::ViewFilesPageIndex);

    setCentralWidget(stackedWidget);

    stackedWidget->setCurrentIndex(Pages::TitlePageIndex); // Show title page

}

MainWindow::~MainWindow()
{
    delete ui;
}
