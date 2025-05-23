#ifndef UPLOADFILEPAGE_H
#define UPLOADFILEPAGE_H

#include <QWidget>

namespace Ui {
class UploadFilePage;
}

class UploadFilePage : public QWidget
{
    Q_OBJECT

public:
    explicit UploadFilePage(QWidget *parent = nullptr);
    ~UploadFilePage();

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
};

#endif // UPLOADFILEPAGE_H
