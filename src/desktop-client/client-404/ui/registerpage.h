#ifndef REGISTERPAGE_H
#define REGISTERPAGE_H

#include <QWidget>
#include <QJsonArray>
#include "ui/basepage.h"
using namespace std;

namespace Ui {
class RegisterPage;
}

class RegisterPage : public BasePage
{
    Q_OBJECT

public:
    explicit RegisterPage(QWidget *parent = nullptr);
    void preparePage() override;
    ~RegisterPage();
    RegisterPage& operator=(const RegisterPage&) = delete;  // Prevent assignment

private slots:
    void onCreateAccountClicked();
    void onShowPasswordClicked();

private:
    Ui::RegisterPage *ui;

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

    // Function to send sign-up request to the server
    bool sendSignUpRequest(const QString& username, const QString& password,const QString& publicKey, QString& signedPreKey, QString& signedPreKeySignature, const QString& salt);

    // Function to send one-time pre-keys to the server
    bool sendOTPksRequest(const QJsonArray& oneTimePreKeysJson);


signals:
    void goToLoginRequested();
    void goToMainMenuRequested();
};

#endif // REGISTERPAGE_H
