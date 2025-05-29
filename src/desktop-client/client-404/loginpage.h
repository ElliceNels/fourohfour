#ifndef LOGINPAGE_H
#define LOGINPAGE_H

#include <QWidget>
#include <QMap>
#include <QDateTime>
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
    string sendCredentials(string name, string password);

private:
    Ui::LoginPage *ui;
    QMap<QString, QList<QDateTime>> loginAttempts;  // IP -> list of attempt timestamps
    bool isRateLimited(const QString& ip);
    void recordLoginAttempt(const QString& ip);
    QString getClientIP();

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToRegisterRequested();
    void goToMainMenuRequested();
};

#endif // LOGINPAGE_H
