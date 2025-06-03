#include "fileitemwidget.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include "constants.h"
#include "utils/widget_utils.h"

FileItemWidget::FileItemWidget(const QString &fileName, const QString &fileFormat, qint64 fileSize, const QString &owner, const bool isOwner, const QString& uuid, QWidget *parent)
    : QWidget(parent)
{
    this->fileExtension = fileFormat;
    this->fileUuid = uuid;
    this->fileSizeBytes = fileSize;
    this->fileNameLabel = UIUtils::createElidedLabel(fileName + "." + fileFormat, fileNameLabelWidth, this);
    
    // Format file size for display
    QString formattedSize = formatFileSize(fileSize);
    this->fileSizeLabel = UIUtils::createElidedLabel(formattedSize, fileSizeLabelWidth, this);
    this->ownerLabel = UIUtils::createElidedLabel(owner, fileOwnerLabelWidth, this);

    // Buttons
    this->previewButton = UIUtils::createIconButton(previewIconPath, this);
    this->downloadButton = UIUtils::createIconButton(downloadIconPath, this);
    if(isOwner){
        this->shareButton = UIUtils::createIconButton(shareIconPath, this);  // only owners can share files
        this->deleteButton = UIUtils::createIconButton(deleteIconPath, this);
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
    emit shareRequested(); 
}

void FileItemWidget::handleDelete() {
    if (UIUtils::confirmAction("Confirm Deletion", "Are you sure you want to delete this file?", this)) {
        // Construct the endpoint URL with the file UUID
        std::string deleteUrl = FILES_API_ENDPOINT + "/" + this->fileUuid.toStdString();
        
        RequestUtils::Response response = LoginSessionManager::getInstance().del(deleteUrl);
        
        // Check the response and show appropriate message
        if (response.success) {
            QMessageBox::information(this, "Success", response.jsonData.object().value("message").toString());
            emit fileDeleted(); // Emit the signal when deletion is successful to trigger UI refresh
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
