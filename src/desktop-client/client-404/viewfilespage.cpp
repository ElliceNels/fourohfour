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

