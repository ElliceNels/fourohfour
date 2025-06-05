#include "permissionwidget.h"
#include <QHBoxLayout>

PermissionWidget::PermissionWidget(const QString &username, QWidget *parent)
    : QWidget(parent), username(username)
{
    // Create layout
    QHBoxLayout *layout = new QHBoxLayout(this);
    layout->setContentsMargins(10, 5, 10, 5);
    
    // Create username label
    usernameLabel = new QLabel(username, this);
    usernameLabel->setStyleSheet("font-size: 14px;");
    
    // Create revoke button
    revokeButton = new QPushButton("Revoke", this);
    revokeButton->setFixedWidth(80);
    revokeButton->setCursor(Qt::PointingHandCursor);
    
    // Add widgets to layout
    layout->addWidget(usernameLabel, 1);
    layout->addWidget(revokeButton, 0);
    
    // Connect signals
    connect(revokeButton, &QPushButton::clicked, [this]() {
        emit revokeRequested(this->username);
    });
    
    setLayout(layout);
}
