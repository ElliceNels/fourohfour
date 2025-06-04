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

protected:
    void showEvent(QShowEvent *event) override;
    void initialisePageUi() override;
    void setupConnections() override;

private slots:
    void onUpdatePasswordClicked();
    void onShowPasswordClicked();
    bool sendResetPasswordRequest(const QString password, const QString newSalt);
    QString getSaltRequest();
    void onBackButtonClicked();

private:
    Ui::ResetPasswordPage *ui;


    QString oldSalt;

};

#endif // RESETPASSWORDPAGE_H
