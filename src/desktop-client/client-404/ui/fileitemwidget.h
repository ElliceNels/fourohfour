#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QString>

class FileItemWidget : public QWidget {
    Q_OBJECT

public:
    FileItemWidget(const QString &fileName, const QString &fileFormat, const QString &fileSize, const QString &owner,const QString uuid, QWidget *parent = nullptr);

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
    QPushButton *downloadButton;
    QPushButton *shareButton;
    QPushButton *deleteButton;
    QPushButton *previewButton;

    QPushButton* createIconButton(const QString& iconPath);
    QLabel* createElidedLabel(const QString &text, int width);

};
