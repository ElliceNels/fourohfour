#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QString>
#include <QMessageBox>
#include <QIcon>
#include <QSize>
#include <QSizePolicy>
#include <QFontMetrics>
#include <QDebug>
#include "core/loginsessionmanager.h"
#include "constants.h"
#include "utils/securebufferutils.h"  // Added include for SodiumZeroDeleter

class FileItemWidget : public QWidget {
    Q_OBJECT

public:
    FileItemWidget(const QString &fileName, const QString &fileFormat, qint64 fileSize, const QString &owner, const bool isOwner, const QString& uuid, QWidget *parent);

signals:
    void fileDeleted(); 
    void shareRequested(); 

private slots:
    void handleDownload();
    void handleShare();
    void handleDelete();
    void handlePreview();

private:
    QLabel *fileNameLabel;
    QLabel *fileSizeLabel;
    QLabel *ownerLabel;
    QString fileExtension;
    QString fileUuid;
    qint64 fileSizeBytes; 
    QPushButton *downloadButton;
    QPushButton *shareButton;
    QPushButton *deleteButton;
    QPushButton *previewButton;

    // UI helper methods
    QPushButton* createIconButton(const QString& iconPath);
    QLabel* createElidedLabel(const QString &text, int width);
    QString formatFileSize(qint64 bytes) const; 
    bool confirmAction(const QString& title, const QString& text);
    
    // Download helper methods
    bool fetchEncryptedFile(QByteArray& encryptedData);
    bool extractFileComponents(const QByteArray& encryptedData, 
                              std::unique_ptr<unsigned char[], SodiumZeroDeleter>& fileNonce, 
                              SecureVector& fileCiphertext);
    QByteArray prepareFileMetadata();
    bool decryptFile(const SecureVector& fileCiphertext,
                   const unsigned char* fileKey,
                   std::unique_ptr<unsigned char[], SodiumZeroDeleter>& fileNonce,
                   const QByteArray& metadataBytes,
                   SecureVector& decryptedFile);
    void saveDecryptedFile(const SecureVector& decryptedFile);
};
