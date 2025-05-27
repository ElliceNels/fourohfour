#ifndef TITLEPAGE_H
#define TITLEPAGE_H

#include <QWidget>

namespace Ui {
class TitlePage;
}

class TitlePage : public QWidget
{
    Q_OBJECT

public:
    explicit TitlePage(QWidget *parent = nullptr);
    ~TitlePage();
    TitlePage& operator=(const TitlePage&) = delete;  // Prevent assignment

private slots:
    void on_signupButton_clicked();
    void on_loginButton_clicked();

private:
    Ui::TitlePage *ui;
};

#endif // TITLEPAGE_H
