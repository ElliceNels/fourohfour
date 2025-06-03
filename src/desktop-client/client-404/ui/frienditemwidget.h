#ifndef FRIENDITEMWIDGET_H
#define FRIENDITEMWIDGET_H

#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QString>
#include <QSizePolicy>
#include <QFontMetrics>
#include <QDebug>
#include <QMessageBox>
#include "utils/widget_utils.h"

class FriendItemWidget : public QWidget {
    Q_OBJECT

public:
    FriendItemWidget(const QString &username, const QString &publicKey, QWidget *parent = nullptr);
    QString getUsername() const { return username; }
    QString getPublicKey() const { return publicKey; }

signals:
    void shareRequested(const QString &username);
    void deleteRequested(const QString &username);

private slots:
    void handleShare();
    void handleDelete();

private:
    QString username;
    QString publicKey;
    QLabel *usernameLabel;
    QPushButton *shareButton;
    QPushButton *deleteButton;
};

#endif // FRIENDITEMWIDGET_H
