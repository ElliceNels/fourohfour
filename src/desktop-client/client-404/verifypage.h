#ifndef VERIFYPAGE_H
#define VERIFYPAGE_H

#include <QWidget>

namespace Ui {
class VerifyPage;
}

class VerifyPage : public QWidget
{
    Q_OBJECT

public:
    explicit VerifyPage(QWidget *parent = nullptr);
    void set_other_public_key(const QByteArray &otherpk);
    ~VerifyPage();
    VerifyPage& operator=(const VerifyPage&) = delete;  // Prevent assignment

private slots:
    void on_verifyButton_clicked();

    void on_backButton_clicked();

private:
    Ui::VerifyPage *ui;
    QByteArray *otherPublicKey;
    QString generate_hash(QString usersPublicKey);
    QString fetch_public_key();
};

#endif
