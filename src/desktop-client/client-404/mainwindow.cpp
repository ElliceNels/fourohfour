#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
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

            QString fileName = fileInfo.fileName();
            qint64 fileSize = fileInfo.size();  // originally in bytes
            QString fileType = fileInfo.suffix();
            QDateTime lastModified = fileInfo.lastModified();
            QDateTime uploadTime = QDateTime::currentDateTime();

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

