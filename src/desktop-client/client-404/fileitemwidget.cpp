#include "FileItemWidget.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include "constants.h"

FileItemWidget::FileItemWidget(const QString &fileName, const QString &fileFormat, const QString &fileSize, const QString &owner, const int id,  QWidget *parent)
    : QWidget(parent)
{

    this->fileExtension = fileFormat;
    this->fileId = id;
    this->fileNameLabel = this->createElidedLabel(fileName + "." + fileFormat, fileNameLabelWidth);
    this->fileSizeLabel = this->createElidedLabel(fileSize, fileSizeLabelWidth);
    this->ownerLabel = this->createElidedLabel(owner, fileOwnerLabelWidth);

    // Buttons
    this->downloadButton = new QPushButton("Download");
    this->shareButton = new QPushButton("Share");

    connect(this->downloadButton, &QPushButton::clicked, this, &FileItemWidget::handleDownload);
    connect(this->shareButton, &QPushButton::clicked, this, &FileItemWidget::handleShare);

    // Layout
    auto *layout = new QHBoxLayout(this);
    layout->addWidget(this->fileNameLabel);
    layout->addWidget(this->fileSizeLabel);
    layout->addWidget(this->ownerLabel);
    layout->addStretch();
    layout->addWidget(this->downloadButton);
    layout->addWidget(this->shareButton);

    this->setLayout(layout);

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
    qDebug() << "Share clicked for file:" << this->fileNameLabel->toolTip();
}
