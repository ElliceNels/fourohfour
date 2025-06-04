#include "widget_utils.h"
#include <QIcon>
#include <QSize>
#include <QSizePolicy>
#include <QFontMetrics>
#include "constants.h"

namespace UIUtils {
    QPushButton* createIconButton(const QString& iconPath, QWidget* parent) {
        QPushButton* button = new QPushButton(parent);
        button->setIcon(QIcon(iconPath));
        button->setIconSize(QSize(20, 20));
        button->setFixedSize(30, 30);
        button->setStyleSheet(Styles::TransparentButton);
        return button;
    }

    QLabel* createElidedLabel(const QString &text, int width, QWidget* parent) {
        QLabel *label = new QLabel(text, parent);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        label->setMinimumWidth(width);
        label->setMaximumWidth(width);
        label->setWordWrap(false);
        label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        label->setToolTip(text);
    
        QFontMetrics metrics(label->font());
        // Use the appropriate truncation factor based on context
        float truncFactor = (width == usernameLabelWidth) ? friendTruncationFactor : truncationFactor;
        QString elided = metrics.elidedText(text, Qt::ElideRight, width * truncFactor);
        label->setText(elided);
    
        return label;
    }

    bool confirmAction(const QString& title, const QString& text, QWidget* parent) {
        QMessageBox msgBox(parent);
        msgBox.setWindowTitle(title);
        msgBox.setText(text);
        msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        msgBox.setDefaultButton(QMessageBox::No);
        
        return (msgBox.exec() == QMessageBox::Yes);
    }
}
