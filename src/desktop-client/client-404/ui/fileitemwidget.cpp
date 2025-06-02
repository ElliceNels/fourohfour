#include "fileitemwidget.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include "constants.h"

FileItemWidget::FileItemWidget(const QString &fileName, const QString &fileFormat, qint64 fileSize, const QString &owner, const bool isOwner, const QString& uuid, QWidget *parent)
    : QWidget(parent)
{

    this->fileExtension = fileFormat;
    this->fileUuid = uuid;
    this->fileSizeBytes = fileSize;
    this->fileNameLabel = this->createElidedLabel(fileName + "." + fileFormat, fileNameLabelWidth);
    
    // Format file size for display
    QString formattedSize = formatFileSize(fileSize);
    this->fileSizeLabel = this->createElidedLabel(formattedSize, fileSizeLabelWidth);
    this->ownerLabel = this->createElidedLabel(owner, fileOwnerLabelWidth);

    // Buttons
    this->previewButton = createIconButton(previewIconPath);
    this->downloadButton = createIconButton(downloadIconPath);
    if(isOwner){
        this->shareButton = createIconButton(shareIconPath);  // only owners can share files
        this->deleteButton = createIconButton(deleteIconPath);
    }
  
    connect(this->downloadButton, &QPushButton::clicked, this, &FileItemWidget::handleDownload);

    if (isOwner) {
        connect(this->shareButton, &QPushButton::clicked, this, &FileItemWidget::handleShare); // only owners can share files
        connect(this->deleteButton, &QPushButton::clicked, this, &FileItemWidget::handleDelete);
    } 

    connect(this->previewButton, &QPushButton::clicked, this, &FileItemWidget::handlePreview);

    // Layout
    auto *layout = new QHBoxLayout(this);
    layout->addWidget(this->fileNameLabel);
    layout->addWidget(this->fileSizeLabel);
    layout->addWidget(this->ownerLabel);
    layout->addStretch();
    layout->addWidget(this->downloadButton);
    if (isOwner) {
        layout->addWidget(this->shareButton);
        layout->addWidget(this->deleteButton);
    }
    layout->addWidget(this->previewButton);


    this->setLayout(layout);

    this->setStyleSheet(Styles::FileItem);
}

QPushButton* FileItemWidget::createIconButton(const QString& iconPath) {
    QPushButton* button = new QPushButton();
    button->setIcon(QIcon(iconPath));
    button->setIconSize(QSize(20, 20));
    button->setFixedSize(30, 30);
    button->setStyleSheet(Styles::TransparentButton);
    return button;
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

// format file size in appropriate units
QString FileItemWidget::formatFileSize(qint64 bytes) const {
    if (bytes < FileUpload::MB) {
        double size = bytes / static_cast<double>(FileUpload::KB);
        return QString("%1 KB").arg(size, 0, 'f', 1);
    } else {
        double size = bytes / static_cast<double>(FileUpload::MB);
        return QString("%1 MB").arg(size, 0, 'f', 2);
    }
}

void FileItemWidget::handleDownload() {
    // download logic here
    qDebug() << "Download clicked for file:" << this->fileNameLabel->toolTip();

}

void FileItemWidget::handleShare() {
    // share logic here
    qDebug() << "Share clicked for file:" << this->fileNameLabel->toolTip();
}

bool FileItemWidget::confirmAction(const QString& title, const QString& text) {
    QMessageBox msgBox;
    msgBox.setWindowTitle(title);
    msgBox.setText(text);
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    
    return (msgBox.exec() == QMessageBox::Yes);
}

void FileItemWidget::handleDelete() {
    if (confirmAction("Confirm Deletion", "Are you sure you want to delete this file?")) {
        // Construct the endpoint URL with the file UUID
        std::string deleteUrl = FILES_API_ENDPOINT + "/" + this->fileUuid.toStdString();
        
        RequestUtils::Response response = LoginSessionManager::getInstance().del(deleteUrl);
        
        // Check the response and show appropriate message
        if (response.success) {
            QMessageBox::information(this, "Success", response.jsonData.object().value("message").toString());
        } else {
            QMessageBox::critical(this, "Error", 
                "Failed to delete file: " + QString::fromStdString(response.errorMessage));
        }
    }
}

void FileItemWidget::handlePreview() {
    // preview logic here
    qDebug() << "Preview clicked for file:" << this->fileNameLabel->toolTip();
}
