#include "basepage.h"
#include <QDebug>

BasePage::BasePage(QWidget *parent) : QWidget(parent)
{
    qDebug() << "Constructing Base Page";
}

void BasePage::initialisePageUi(){
     qDebug() << "BasePage initialisePageUi";
}

void BasePage::preparePage()
{
    qDebug() << "Preparing Base Page";
}

BasePage::~BasePage()
{
    qDebug() << "Destroying Base Page";
}
