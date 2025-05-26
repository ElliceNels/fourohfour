#ifndef VIEWFILESPAGE_H
#define VIEWFILESPAGE_H

#include <QWidget>

namespace Ui {
class ViewFilesPage;
}

class ViewFilesPage : public QWidget
{
    Q_OBJECT

public:
    explicit ViewFilesPage(QWidget *parent = nullptr);
    ~ViewFilesPage();

private slots:
    void on_backButton_clicked();


private:
    Ui::ViewFilesPage *ui;
};

#endif // VIEWFILESPAGE_H
