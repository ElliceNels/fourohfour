#include "mainwindow.h"
#include "ui/ui_mainwindow.h"
#include "ui/registerpage.h"
#include "ui/titlepage.h"
#include "ui/loginpage.h"
#include "ui/verifypage.h"
#include "pages.h"
#include "constants.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    this->ui->setupUi(this);

    this->stackedWidget = new QStackedWidget(this);
    this->stackedWidget->setStyleSheet(Styles::CentralWidget);


    // BasePage is an abstract class (has at least one pure virtual function) so cannot be instantiated
    // Uncomment the line below to see the warning and error that appear
    //BasePage* bpPtr = new BasePage();

    /*
     * mainwindow.cpp:22:27: Allocating an object of abstract class type 'BasePage'
     * basepage.h:19:18: unimplemented pure virtual method 'initialisePageUi' in 'BasePage'
     * basepage.h:22:18: unimplemented pure virtual method 'setupConnections' in 'BasePage'
    */

    // Demonstrate Runtime polymorphism by creating pages as BasePages first
    this->titlePage = this->createAndAddPage<TitlePage>(this, this->stackedWidget);
    this->registerPage = this->createAndAddPage<RegisterPage>(this, this->stackedWidget);
    this->loginPage = this->createAndAddPage<LoginPage>(this, this->stackedWidget);
    this->verifyPage = this->createAndAddPage<VerifyPage>(this, this->stackedWidget);
    this->uploadFilePage = this->createAndAddPage<UploadFilePage>(this, this->stackedWidget);
    this->mainMenu = this->createAndAddPage<MainMenu>(this, this->stackedWidget);
    this->resetPasswordPage = this->createAndAddPage<ResetPasswordPage>(this, this->stackedWidget);
    this->viewFilesPage = this->createAndAddPage<ViewFilesPage>(this, this->stackedWidget);


    //Operator overloading
    *stackedWidget + titlePage;
    *stackedWidget + registerPage;
    *stackedWidget + loginPage;
    *stackedWidget + verifyPage;
    *stackedWidget + uploadFilePage;
    *stackedWidget + mainMenu;
    *stackedWidget + resetPasswordPage;
    *stackedWidget + viewFilesPage;


    // Title page navigation
    this->connectPageNavigation(this->titlePage, &TitlePage::goToRegisterRequested, Pages::RegisterPageIndex);
    this->connectPageNavigation(this->titlePage, &TitlePage::goToLoginRequested, Pages::LoginPageIndex);

    // Login/Register navigation
    this->connectPageNavigation(this->loginPage, &LoginPage::goToRegisterRequested, Pages::RegisterPageIndex);
    this->connectPageNavigation(this->registerPage, &RegisterPage::goToLoginRequested, Pages::LoginPageIndex);

    // Back to main menu navigation
    this->connectPageNavigation(this->verifyPage, &VerifyPage::goToMainMenuRequested, Pages::MainMenuIndex);
    this->connectPageNavigation(this->uploadFilePage, &UploadFilePage::goToMainMenuRequested, Pages::MainMenuIndex);
    this->connectPageNavigation(this->viewFilesPage, &ViewFilesPage::goToMainMenuRequested, Pages::MainMenuIndex);
    this->connectPageNavigation(this->loginPage, &LoginPage::goToMainMenuRequested, Pages::MainMenuIndex);
    this->connectPageNavigation(this->registerPage, &RegisterPage::goToMainMenuRequested, Pages::MainMenuIndex);

    // Main menu navigation
    this->connectPageNavigation(this->mainMenu, &MainMenu::goToUploadFilePageRequested, Pages::UploadFilePageIndex);
    this->connectPageNavigation(this->mainMenu, &MainMenu::goToVerifyPageRequested, Pages::VerifyPageIndex);
    this->connectPageNavigation(this->mainMenu, &MainMenu::goToLoginPageRequested, Pages::LoginPageIndex);
    this->connectPageNavigation(this->mainMenu, &MainMenu::goToViewFilesPageRequested, Pages::ViewFilesPageIndex);
    this->connectPageNavigation(this->mainMenu, &MainMenu::goToResetPasswordRequested, Pages::ResetPasswordPage);

    this->setCentralWidget(this->stackedWidget);

    this->stackedWidget->setCurrentIndex(Pages::TitlePageIndex); // Show title page
}

MainWindow::~MainWindow()
{
    delete this->ui;
}
