#ifndef LOGINPAGE_H
#define LOGINPAGE_H
#include <QWidget>
#include <QMap>
#include <QDateTime>

using namespace std;

namespace Ui {
class LoginPage;
}

class LoginPage : public QWidget
{
    Q_OBJECT

public:
    explicit LoginPage(QWidget *parent = nullptr);
    ~LoginPage();

private slots:
    void onLoginButtonClicked();
    void onShowPasswordClicked();
    void sendCredentials(string name, string password);

private:
    Ui::LoginPage *ui;
    QMap<QString, QList<QDateTime>> loginAttempts;  // IP -> list of attempt timestamps
    bool isRateLimited(const QString& ip);
    void recordLoginAttempt(const QString& ip);
    QString getClientIP();

signals:
    void goToRegisterRequested();
};

#endif // LOGINPAGE_H
