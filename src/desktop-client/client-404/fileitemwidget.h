#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QString>

class FileItemWidget : public QWidget {
    Q_OBJECT

public:
    FileItemWidget(const QString &fileName, const QString &fileFormat, const QString &fileSize, const QString &owner,const int id, QWidget *parent = nullptr);

private slots:
    void handleDownload();
    void handleShare();

private:
    QLabel *fileNameLabel;
    QLabel *fileSizeLabel;
    QLabel *ownerLabel;
    QString fileExtension;
    int fileId;
    QPushButton *downloadButton;
    QPushButton *shareButton;

    QLabel* createElidedLabel(const QString &text, int width);

};
