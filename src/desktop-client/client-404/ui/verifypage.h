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
    void set_other_public_key(const QByteArray &otherpk);
    void preparePage() override;
    ~VerifyPage();
    VerifyPage& operator=(const VerifyPage&) = delete;  // Prevent assignment

private slots:
    void on_verifyButton_clicked();
    void on_acceptButton_clicked();
    void on_rejectButton_clicked();

private:
    Ui::VerifyPage *ui;
    QByteArray *otherPublicKey;
    QString generate_hash(QString usersPublicKey);
    QString fetch_public_key();

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

    void switchPages(int pageIndex);
    void publicKeyCleanup();
    void showFriendshipStatus(bool accepted);
    void toggleUIElements(bool show);
    void setButtonsEnabled(bool enabled);

signals:
    void goToMainMenuRequested();
};

#endif
