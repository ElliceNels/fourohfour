#ifndef VERIFYPAGE_H
#define VERIFYPAGE_H

#include <QWidget>
#include "basepage.h"

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

private slots:
    void on_verifyButton_clicked();

private:
    Ui::VerifyPage *ui;
    QByteArray *otherPublicKey;
    QString generate_hash(QString usersPublicKey);
    QString fetch_public_key();

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToMainMenuRequested();
};

#endif
