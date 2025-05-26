#ifndef LOGINPAGE_H
#define LOGINPAGE_H
#include <QWidget>

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

signals:
    void goToRegisterRequested();
};

#endif // LOGINPAGE_H
