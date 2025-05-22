#include "titlepage.h"
#include "ui_titlepage.h"
#include <QStackedWidget>

TitlePage::TitlePage(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::TitlePage)
{
    ui->setupUi(this);
}

TitlePage::~TitlePage()
{
    delete ui;
}

void TitlePage::on_signupButton_clicked()
{
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(1);
    }
}


