#include "mainmenu.h"
#include "pages.h"
#include "ui_mainmenu.h"
#include <qstackedwidget.h>

MainMenu::MainMenu(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::MainMenu)
{
    ui->setupUi(this);
}

MainMenu::~MainMenu()
{
    delete ui;
}

void MainMenu::on_uploadButton_clicked()
{
    // Switch to upload file page
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(Pages::UploadFilePageIndex);
    }
}


void MainMenu::on_verifyButton_clicked()
{
    // Switch to verify user page
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(Pages::VerifyPageIndex);
    }
}

