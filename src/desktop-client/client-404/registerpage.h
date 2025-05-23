#ifndef REGISTERPAGE_H
#define REGISTERPAGE_H

#include <QWidget>

using namespace std;

namespace Ui {
class RegisterPage;
}

class RegisterPage : public QWidget
{
    Q_OBJECT

public:
    explicit RegisterPage(QWidget *parent = nullptr);
    ~RegisterPage();

private slots:
    void onCreateAccountClicked();
    void onShowPasswordClicked();
    void sendCredentials(string name, string email, string password, string publicKey, string salt);

private:
    Ui::RegisterPage *ui;

signals:
    void goToLoginRequested();
};

#endif // REGISTERPAGE_H
