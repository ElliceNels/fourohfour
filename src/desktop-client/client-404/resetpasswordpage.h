#ifndef RESETPASSWORDPAGE_H
#define RESETPASSWORDPAGE_H

#include <QWidget>

using namespace std;

namespace Ui {
class ResetPasswordPage;
}

class ResetPasswordPage : public QWidget
{
    Q_OBJECT

public:
    explicit ResetPasswordPage(QWidget *parent = nullptr);
    ~ResetPasswordPage();

private slots:
    void onUpdatePasswordClicked();
    void onShowPasswordClicked();
    void sendCredentials(string password, string salt);
    void fetchAndStoreSalt();

private:
    Ui::ResetPasswordPage *ui;
    QString oldSalt;

};

#endif // RESETPASSWORDPAGE_H

