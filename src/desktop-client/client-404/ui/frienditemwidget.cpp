#include "frienditemwidget.h"
#include <QIcon>
#include <QSize>
#include "constants.h"
#include "utils/widget_utils.h"

FriendItemWidget::FriendItemWidget(const QString &username, const QString &publicKey, QWidget *parent)
    : QWidget(parent), username(username), publicKey(publicKey)
{
    // Create username label with elided text
    this->usernameLabel = UIUtils::createElidedLabel(username, usernameLabelWidth, this);
    
    // Create buttons with icons
    this->shareButton = UIUtils::createIconButton(shareIconPath, this);
    this->deleteButton = UIUtils::createIconButton(deleteIconPath, this);
    
    // Add tooltips to the buttons
    this->shareButton->setToolTip("Share with this friend");
    this->deleteButton->setToolTip("Delete friendship");
    
    // Connect buttons to their handlers
    connect(this->shareButton, &QPushButton::clicked, this, &FriendItemWidget::handleShare);
    connect(this->deleteButton, &QPushButton::clicked, this, &FriendItemWidget::handleDelete);
    
    // Layout
    auto *layout = new QHBoxLayout(this);
    layout->addWidget(this->usernameLabel);
    layout->addStretch();
    layout->addWidget(this->shareButton);
    layout->addWidget(this->deleteButton);
    
    this->setLayout(layout);
    
    // Apply styling
    this->setStyleSheet(Styles::FileItem); // Reuse the FileItem style for consistency
}

void FriendItemWidget::handleShare() {
    // Emit signal with username when share button is clicked
    emit shareRequested(username);
    qDebug() << "Share requested for friend:" << username;
}

void FriendItemWidget::handleDelete() {
    if (UIUtils::confirmAction("Confirm Removal", "Are you sure you want to remove this friend?", this)) {
        emit deleteRequested(username);
        qDebug() << "Delete requested for friend:" << username;
    }
}
