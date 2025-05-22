#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "registerpage.h"
#include "loginpage.h"

constexpr qint64 MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024;  // 100 MB in bytes

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    stackedWidget = new QStackedWidget(this);
    stackedWidget->setStyleSheet("background-color: #66a3ff;");

    registerPage = new RegisterPage(this);
    loginPage = new LoginPage(this);

    stackedWidget->addWidget(registerPage);// index 0
    stackedWidget->addWidget(loginPage); // index 1

    connect(loginPage, &LoginPage::goToRegisterRequested, this, [this]() {
        stackedWidget->setCurrentIndex(0);
    });

    connect(registerPage, &RegisterPage::goToLoginRequested, this, [this]() {
        stackedWidget->setCurrentIndex(1);
    });

    setCentralWidget(stackedWidget);

    stackedWidget->setCurrentIndex(1); // Show login page

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_uploadButton_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Open File", "", "All Files (*.*)");

    if (!filePath.isEmpty()) {
        QFileInfo fileInfo(filePath);

        // Gets the metadata that won't be encrypted but will be authentication
        QString fileName = fileInfo.completeBaseName();
        qint64 fileSize = fileInfo.size();  // originally in bytes
        QString fileType = fileInfo.suffix();
        QDateTime lastModified = fileInfo.lastModified();
        QDateTime uploadTime = QDateTime::currentDateTime();

        if (fileSize > MAX_FILE_SIZE_BYTES) {
            ui->textEdit->setText("File exceeds 100MB limit");
            return;
        }

        // Gets the actual file data to be encrypted
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            ui->textEdit->setText("Failed to open file.");
            return;
        }
        QByteArray fileData = file.readAll();
        file.close();

        QString info = QString(
                           "File Name: %1\n"
                           "File Size: %2 bytes\n"
                           "File Type: %3\n"
                           "Last Modified: %4\n"
                           "Upload Time: %5")
                           .arg(fileName)
                           .arg(fileSize)
                           .arg(fileType)
                           .arg(lastModified.toString("yyyy-MM-dd hh:mm:ss"))
                           .arg(uploadTime.toString("yyyy-MM-dd hh:mm:ss"));

        ui->textEdit->setText(info);
    }
}
