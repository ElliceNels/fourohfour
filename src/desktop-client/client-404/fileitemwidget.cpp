#include "FileItemWidget.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include "constants.h"

FileItemWidget::FileItemWidget(const QString &fileName, const QString &fileFormat, const QString &fileSize, const QString &owner, const int id,  QWidget *parent)
    : QWidget(parent)
{

    this->fileExtension = fileFormat;
    this->fileId = id;
    fileNameLabel = createElidedLabel(fileName + "." + fileFormat, fileNameLabelWidth);
    fileSizeLabel = createElidedLabel(fileSize, fileSizeLabelWidth);
    ownerLabel = createElidedLabel(owner, fileOwnerLabelWidth);

    // Buttons
    downloadButton = new QPushButton("Download");
    shareButton = new QPushButton("Share");

    connect(downloadButton, &QPushButton::clicked, this, &FileItemWidget::handleDownload);
    connect(shareButton, &QPushButton::clicked, this, &FileItemWidget::handleShare);

    // Layout
    auto *layout = new QHBoxLayout(this);
    layout->addWidget(fileNameLabel);
    layout->addWidget(fileSizeLabel);
    layout->addWidget(ownerLabel);
    layout->addStretch();
    layout->addWidget(downloadButton);
    layout->addWidget(shareButton);

    setLayout(layout);

    this->setStyleSheet(Styles::FileItem);
}

QLabel* FileItemWidget::createElidedLabel(const QString &text, int width) {
    QLabel *label = new QLabel(text);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    label->setMinimumWidth(width);
    label->setMaximumWidth(width);
    label->setWordWrap(false);
    label->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    label->setToolTip(text);

    QFontMetrics metrics(label->font());
    QString elided = metrics.elidedText(text, Qt::ElideRight, width * truncationFactor);
    label->setText(elided);

    return label;
}

void FileItemWidget::handleDownload() {
    // download logic here
    qDebug() << "Download clicked for file:" << this->fileNameLabel->toolTip();

}

void FileItemWidget::handleShare() {
    // share logic here
    qDebug() << "Share clicked for file:" << fileNameLabel->toolTip();
}
