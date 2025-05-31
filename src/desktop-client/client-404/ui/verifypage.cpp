#include "verifypage.h"
#include "ui/ui_verifypage.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <qstackedwidget.h>
#include <QThread>
#include <sodium.h>
#include "constants.h"
#include <QTimer>

VerifyPage::VerifyPage(QWidget *parent)
    : BasePage(parent)
    ,ui(new Ui::VerifyPage)
{
    qDebug() << "Constructing and setting up Verify Page";
}
void VerifyPage::preparePage(){
    qDebug() << "Preparing Verify Page";
    this->initialisePageUi();    // Will call the derived class implementation
    this->setupConnections();    // Will call the derived class implementation
}

void VerifyPage::initialisePageUi(){
    this->ui->setupUi(this);
    toggleUIElements(false); // Hide all certain ui  elements initially
}

void VerifyPage::setupConnections(){
    connect(this->ui->verify_backButton, &QPushButton::clicked,this, [this]() { switchPages(FIND_FRIEND_INDEX); });
    connect(this->ui->findFriend_backButton, &QPushButton::clicked, this, &VerifyPage::goToMainMenuRequested);
    connect(this->ui->findButton, &QPushButton::clicked, this, [this]() {switchPages(VERIFY_PUBLIC_KEY_INDEX);} );
    connect(this->ui->rejectButton, &QPushButton::clicked, this, [this]() {on_rejectButton_clicked(); });
    connect(this->ui->acceptButton, &QPushButton::clicked, this, [this]() {on_acceptButton_clicked(); });
}

void VerifyPage::set_other_public_key(const QByteArray &otherpk){
    this->otherPublicKey = otherpk; 
}

QString VerifyPage::fetch_public_key(){
    QString filePath = QFileDialog::getOpenFileName(this, "Open File", "", "JSON Files (*.json)");

    if (!filePath.isEmpty()) {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Error", "Could not open the file.");
            return QString();
        }

        // Parsing of the keys from the JSON file
        QByteArray jsonData = file.readAll();
        file.close();

        QJsonParseError parseError;
        QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonData, &parseError);

        if (parseError.error != QJsonParseError::NoError) {
            QMessageBox::warning(this, "Parse Error", "Failed to parse JSON: " + parseError.errorString());
            return QString();
        }

        if (jsonDoc.isObject()){
            QJsonObject jsonObj = jsonDoc.object();

            if (jsonObj.contains("publicKey") && jsonObj["publicKey"].isString()) {
                return jsonObj["publicKey"].toString();
            } else {
                QMessageBox::warning(this, "Error", "Unable to fetch your public key");
                return QString();
            }
        }
    }
    return QString();
}

QString VerifyPage::generate_hash(QString usersPublicKey){
    if (usersPublicKey.isEmpty() || this->otherPublicKey.isEmpty()) {
        return QString();
    }

    QByteArray encodedUserPK = usersPublicKey.toUtf8();

    // Ensures there is a consistent order of concatenation cross device
    QByteArray concatenated;
    if (encodedUserPK < this->otherPublicKey) {
        concatenated = encodedUserPK + this->otherPublicKey;
    } else {
        concatenated = this->otherPublicKey + encodedUserPK;
    }

    // Hash the combination of keys
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, reinterpret_cast<const unsigned char*>(concatenated.constData()), concatenated.size());

    // Convert the hash into a readable form to display on the this->ui
    QString hexHash;
    for (int i = 0; i < crypto_hash_sha256_BYTES; i++) {
        hexHash.append(QString::asprintf("%02x", hash[i]));
    }

    return hexHash;
}

void VerifyPage::on_verifyButton_clicked(){
    // This is placeholder until we fetch the public key from the database
    QByteArray placeholder_other_pk = QString("mZ3bW1x8F9j0XQeP7CqyLkA6wE9vFt9hRYKdJPngq+Q=").toUtf8();
    set_other_public_key(placeholder_other_pk);

    QString publicKey = this->fetch_public_key();

    if (publicKey.isEmpty()){
        // No need to show an error message here, as the fetch_public_key already does that
        return;
    }

    QString hash = this->generate_hash(publicKey);

    if (hash.isEmpty()){
        QMessageBox::warning(this, "Error", "Could not generate hash");
        return;
    }

    this->ui->displayLineEdit->setText(hash);

    toggleUIElements(true); // Show the UI elements for acceptance/rejection
}

void VerifyPage::on_rejectButton_clicked() {
    setButtonsEnabled(false);
    showFriendshipStatus(false);
}

void VerifyPage::on_acceptButton_clicked() {
    // TODO: Implement the logic to accept the friendship and store it locally
    setButtonsEnabled(false);
    showFriendshipStatus(true);
}

void VerifyPage::showFriendshipStatus(bool accepted) {
    // Set message and color based on acceptance status
    if (accepted) {
        this->ui->acceptanceResultLabel->setText("Friendship accepted!");
        this->ui->acceptanceResultLabel->setStyleSheet(Styles::SuccessMessage);
    } else {
        this->ui->acceptanceResultLabel->setText("Friendship rejected!");
        this->ui->acceptanceResultLabel->setStyleSheet(Styles::ErrorMessage);
    }
    
    // Show the label
    this->ui->acceptanceResultLabel->show();
    
    // Disable all buttons to prevent multiple clicks during animation
    // Use QTimer instead of sleep to avoid blocking UI thread
    QTimer* timer = new QTimer(this);
    timer->setSingleShot(true);
    
    // Connect the timer to perform navigation after timeout
    connect(timer, &QTimer::timeout, this, [this, accepted, timer]() {
        if (accepted) {
            // For acceptance, go to main menu
            emit this->goToMainMenuRequested();
            switchPages(FIND_FRIEND_INDEX);
        } else {
            // For rejection, go back to find friend page
            switchPages(FIND_FRIEND_INDEX);
        }
        // Clean up the timer
        timer->deleteLater();
    });
    
    // Start the timer for 1.5 seconds (1500 ms)
    timer->start(1500);
}


void VerifyPage::toggleUIElements(bool show) {
    if (show){
        this->ui->acceptButton->show();
        this->ui->rejectButton->show();
        this->ui->acceptanceInfoLabel->show();
    } else {
        this->ui->displayLineEdit->setText("No key file selected...");
        this->ui->acceptButton->hide();
        this->ui->rejectButton->hide();
        this->ui->acceptanceInfoLabel->hide();
        this->ui->acceptanceResultLabel->hide();
    }
  
}

void VerifyPage::setButtonsEnabled(bool enabled) {
    this->ui->verifyButton->setEnabled(enabled);
    this->ui->acceptButton->setEnabled(enabled);
    this->ui->rejectButton->setEnabled(enabled);
}

void VerifyPage::switchPages(int pageIndex) {
    ui->contentStackedWidget->setCurrentIndex(pageIndex);
    if (pageIndex == FIND_FRIEND_INDEX) {
        this->otherPublicKey.clear();  // Simply clear the QByteArray
        toggleUIElements(false); // Hide all UI elements
    }
    setButtonsEnabled(true);
}

VerifyPage::~VerifyPage()
{
    qDebug() << "Destroying Verify Page";
    delete this->ui;
    
}
