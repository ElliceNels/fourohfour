#ifndef RESETPASSWORDPAGE_H
#define RESETPASSWORDPAGE_H

#include <QWidget>
#include "basepage.h"

using namespace std;

namespace Ui {
class ResetPasswordPage;
}

class ResetPasswordPage : public BasePage
{
    Q_OBJECT

public:
    explicit ResetPasswordPage(QWidget *parent = nullptr);
    void preparePage() override;
    ~ResetPasswordPage();

private slots:
    void onUpdatePasswordClicked();
    void onShowPasswordClicked();
    bool sendResetPasswordRequest(const QString password, const QString newSalt);
    QString getSaltRequest();

private:
    Ui::ResetPasswordPage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

    QString oldSalt;

};

#endif // RESETPASSWORDPAGE_H
