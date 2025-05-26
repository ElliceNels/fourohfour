#ifndef BASEPAGE_H
#define BASEPAGE_H

#include <QWidget>

class BasePage : public QWidget
{
    Q_OBJECT
public:
    explicit BasePage(QWidget *parent = nullptr);
    virtual void preparePage();
    virtual ~BasePage(); // virtual destructor for a correct object deletion sequence

protected:

    // These are the pure virtual functions that all derived classes must implement

    // pure as only the derived classes can call the ui->setupUi(this) for their own pages
    virtual void initialisePageUi();

    // pure as the derived classes have their individual connections each
    virtual void setupConnections() = 0;

};

#endif // BASEPAGE_H
