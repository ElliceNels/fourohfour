#ifndef LOGINPAGE_H
#define LOGINPAGE_H

#include <QWidget>
#include "basepage.h"

using namespace std;

namespace Ui {
class LoginPage;
}

class LoginPage : public BasePage
{
    Q_OBJECT

public:
    explicit LoginPage(QWidget *parent = nullptr);
    void preparePage() override;
    ~LoginPage();
    LoginPage& operator=(const LoginPage&) = delete;  // Prevent assignment

private slots:
    void onLoginButtonClicked();
    void onShowPasswordClicked();

private:
    Ui::LoginPage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToRegisterRequested();
    void goToMainMenuRequested();
};

#endif // LOGINPAGE_H
