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
#include "utils/widget_utils.h"

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

    // Format file size in a human-readable form
    QString formatFileSize(qint64 bytes) const;
};
