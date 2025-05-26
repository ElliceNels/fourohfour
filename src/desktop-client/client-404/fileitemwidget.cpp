// FileItemWidget.cpp
#include "FileItemWidget.h"
#include <qlabel.h>
#include <qpushbutton.h>

FileItemWidget::FileItemWidget(const QString &fileName, const QString &fileFormat, const QString &fileSize, const QString &owner, QWidget *parent)
    : QWidget(parent)
{

    this->fileExtension = fileFormat;
    fileNameLabel = createElidedLabel(fileName + "." + fileFormat, 200);
    fileSizeLabel = createElidedLabel(fileSize, 60);
    ownerLabel = createElidedLabel(owner, 100);

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

    this->setStyleSheet(R"(
        QWidget {
            background-color: #E7ECEF;
            border-bottom: 1px solid #8B8C89;
            padding: 8px;
        }

        QLabel {
            color: #274C77;
            font-weight: bold;
        }

        QPushButton {
            background-color: #6096BA;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
        }

        QPushButton:hover {
            background-color: #A3CEF1;
        }
    )");
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
    QString elided = metrics.elidedText(text, Qt::ElideRight, width * 0.75);
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
