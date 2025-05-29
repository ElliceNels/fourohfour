#ifndef UPLOADFILEPAGE_H
#define UPLOADFILEPAGE_H

#include <QWidget>
#include "basepage.h"
#include "securevector.h"

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

    bool encryptUploadedFile();
    QByteArray formatFileMetadata();
    bool SaveKeyToLocalStorage(const QString &fileUuid,const unsigned char *key, size_t keyLen);
    bool validateKeyParameters(const unsigned char *key, size_t keyLen);
    bool validateMasterKey(const SecureVector &masterKey);
    QString buildKeyStorageFilePath();
    bool readAndDecryptKeyStorage(const QString &filepath, 
                                 const SecureVector &masterKey, 
                                 QByteArray &jsonData);
    bool addKeyToJsonStorage(const QByteArray &jsonData,
                            const QString &fileUuid,
                            const unsigned char *key,
                            size_t keyLen,
                            QByteArray &updatedJsonData);
    bool encryptAndSaveKeyStorage(const QString &filepath,
                                const QByteArray &jsonData,
                                const SecureVector &masterKey);

    // Overridden methods from BasePage abstract class
    void initialisePageUi() override;
    void setupConnections() override;

signals:
    void goToMainMenuRequested();

};

#endif // UPLOADFILEPAGE_H
