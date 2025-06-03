#ifndef VERIFYPAGE_H
#define VERIFYPAGE_H

#include <QWidget>
#include "ui/basepage.h"

namespace Ui {
class VerifyPage;
}

class VerifyPage : public BasePage
{
    Q_OBJECT

public:
    explicit VerifyPage(QWidget *parent = nullptr);
    void preparePage() override;
    ~VerifyPage();
    VerifyPage& operator=(const VerifyPage&) = delete;  // Prevent assignment

private slots:
    void on_verifyButton_clicked();
    void on_acceptButton_clicked();
    void on_rejectButton_clicked();
    void on_findButton_clicked();

private:
    Ui::VerifyPage *ui;
    QByteArray otherPublicKey;
    QString otherUsername;  
    QString generate_hash(QString usersPublicKey);
    QString fetch_local_public_key();
    bool fetch_server_public_key(const QString& username);


    bool saveFriendPairToJSON();
    bool validateFriendData();

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

    void switchPages(int pageIndex);
    void toggleVerificationAcceptanceControls(bool show);
    void setButtonsEnabled(bool enabled);
    bool validateUsername(const QString& username);

signals:
    void goToMainMenuRequested();
};

#endif
