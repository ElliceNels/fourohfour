#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "registerpage.h"
// #include "loginpage.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    stackedWidget = new QStackedWidget(this);

    registerPage = new RegisterPage(this);
    stackedWidget->addWidget(registerPage); // index 0

    stackedWidget->setStyleSheet("background-color: #66a3ff;");

    // loginPage = new LoginPage(this);
    // stackedWidget->addWidget(loginPage); // index 1

    setCentralWidget(stackedWidget);

    // stackedWidget->setCurrentIndex(1); // Show login page
}

MainWindow::~MainWindow()
{
    delete ui;
}
