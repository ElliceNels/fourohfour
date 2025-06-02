#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QString>

class FileItemWidget : public QWidget {
    Q_OBJECT

public:
    FileItemWidget(const QString &fileName, const QString &fileFormat, qint64 fileSize, const QString &owner, const bool isOwner, const QString& uuid, QWidget *parent);

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

    QPushButton* createIconButton(const QString& iconPath);
    QLabel* createElidedLabel(const QString &text, int width);
    QString formatFileSize(qint64 bytes) const; 
};
