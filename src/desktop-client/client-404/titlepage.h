#ifndef TITLEPAGE_H
#define TITLEPAGE_H

#include <QWidget>
#include "basepage.h"

namespace Ui {
class TitlePage;
}

class TitlePage : public BasePage
{
    Q_OBJECT

public:
    explicit TitlePage(QWidget *parent = nullptr);
    void preparePage() override;
    ~TitlePage();
    TitlePage& operator=(const TitlePage&) = delete;  // Prevent assignment

private:
    Ui::TitlePage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToRegisterRequested();
    void goToLoginRequested();
};

#endif // TITLEPAGE_H
