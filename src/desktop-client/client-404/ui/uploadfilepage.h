#ifndef UPLOADFILEPAGE_H
#define UPLOADFILEPAGE_H

#include <QWidget>
#include "ui/basepage.h"
#include "utils/securevector.h"

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
    
    void tryEncryptAndUploadFile();
    QString uploadFileToServer(const SecureVector& encryptedData, 
                              const QString& fileUuid = QString(), 
                              const QString& successMessage = QString());
    QByteArray formatFileMetadata();
    bool showOverwriteConfirmation();
    QString reuploadWithUuid(const SecureVector& encryptedData, const QString& fileUuid);
    
    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToMainMenuRequested();

};

#endif // UPLOADFILEPAGE_H
