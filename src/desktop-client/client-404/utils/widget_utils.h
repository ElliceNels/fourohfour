#ifndef WIDGET_UTILS_H
#define WIDGET_UTILS_H

#include <QPushButton>
#include <QLabel>
#include <QWidget>
#include <QString>
#include <QMessageBox>

namespace UIUtils {
    // Creates a standardized icon button for UI elements
    QPushButton* createIconButton(const QString& iconPath, QWidget* parent = nullptr);
    
    // Creates a label with elided text that fits within a specified width
    QLabel* createElidedLabel(const QString &text, int width, QWidget* parent = nullptr);
    
    // Shows a confirmation dialog and returns true if "Yes" was selected
    bool confirmAction(const QString& title, const QString& text, QWidget* parent = nullptr);
}

#endif // WIDGET_UTILS_H
