#include "viewfilespage.h"
#include "pages.h"
#include "ui_viewfilespage.h"
#include <qstackedwidget.h>
#include "fileitemwidget.h"

ViewFilesPage::ViewFilesPage(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::ViewFilesPage)
{
    ui->setupUi(this);

    FileItemWidget *fileItem = new FileItemWidget("examplesdyuisrtyuihsrtyihfdtyuigfdtexamplesdyuisrtyuihsrtyihfdtyuigfdtyy", "txt", "15 KB", "User123");
    FileItemWidget *fileItem2 = new FileItemWidget("example2", "txt", "64 KB", "User");

    // Create the QListWidgetItem to hold it
    QListWidgetItem *listItem = new QListWidgetItem(ui->listWidget);
    QListWidgetItem *listItem2 = new QListWidgetItem(ui->listWidget);

    // Match the widget's height
    listItem->setSizeHint(fileItem->sizeHint());
    listItem2->setSizeHint(fileItem2->sizeHint());

    // Add to QListWidget
    ui->listWidget->addItem(listItem);
    ui->listWidget->setItemWidget(listItem, fileItem);
    ui->listWidget->setItemWidget(listItem2, fileItem2);
}

ViewFilesPage::~ViewFilesPage()
{
    delete ui;
}

void ViewFilesPage::on_backButton_clicked()
{
    // Switch back to main menu
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(Pages::MainMenuIndex);
    }
}

