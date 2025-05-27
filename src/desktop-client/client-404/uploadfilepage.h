#ifndef UPLOADFILEPAGE_H
#define UPLOADFILEPAGE_H

#include <QWidget>
#include "basepage.h"

namespace Ui {
class UploadFilePage;
}

class UploadFilePage : public BasePage
{
    Q_OBJECT

public:
    explicit UploadFilePage(QWidget *parent = nullptr);
    void preparePage() override;
    ~UploadFilePage();
    UploadFilePage& operator=(const UploadFilePage&) = delete;  // Prevent assignment

private slots:
    void on_uploadButton_clicked();
    void on_confirmButton_clicked();

private:
    Ui::UploadFilePage *ui;

    QString fileName;
    QString fileType;
    qint64 fileSize;
    QByteArray fileData;

    void encryptUploadedFile();
    QByteArray formatFileMetadata();

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToMainMenuRequested();

};

#endif // UPLOADFILEPAGE_H
