#ifndef REGISTERPAGE_H
#define REGISTERPAGE_H

#include <QWidget>
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
    bool sendSignUpRequest(const QString& username, const QString& hashedPassword, 
                                    const QString& publicKey, const QString& salt);


signals:
    void goToLoginRequested();
    void goToMainMenuRequested();
};

#endif // REGISTERPAGE_H
