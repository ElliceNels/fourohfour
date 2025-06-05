#ifndef PERMISSIONWIDGET_H
#define PERMISSIONWIDGET_H

#include <QWidget>
#include <QString>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>

class PermissionWidget : public QWidget
{
    Q_OBJECT

public:
    explicit PermissionWidget(const QString &username, QWidget *parent = nullptr);
    ~PermissionWidget() = default;
    
signals:
    void revokeRequested(const QString &username);

private:
    QString username;
    QLabel *usernameLabel;
    QPushButton *revokeButton;
};

#endif // PERMISSIONWIDGET_H
