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
#include "utils/request_utils.h"
#include "loginsessionmanager.h"

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
}

QString VerifyPage::fetch_local_public_key(){
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

bool VerifyPage::fetch_server_public_key(const QString& username){
    // Create params for the GET request
    QJsonObject params;
    params["username"] = username;

    // Make the GET request to retrieve the public key
    RequestUtils::Response response = LoginSessionManager::getInstance().get(GET_PUBLIC_KEY_ENDPOINT, params);

    if (response.success) {
        QJsonObject jsonObject = response.jsonData.object();
        if (jsonObject.contains("public_key")) {
            // Extract public key from response
            QString publicKey = jsonObject["public_key"].toString();
            
            // Store the public key for later use
            this->otherPublicKey = publicKey.toUtf8();
            
            qDebug() << "Public key retrieved for user: " << this->otherPublicKey;
            
            QMessageBox::information(this, "Success", 
                "Successfully retrieved public key for: " + username);
            return true;
        } else {
            QMessageBox::warning(this, "Error", "Public key not found in response");
        }
    } else {
       QMessageBox::critical(this, "Public Key Fetch Error", 
        "Failed to fetch public key for user: " + username + "\nError: " + QString::fromStdString(response.errorMessage));
    }
    
    return false; // Return false if the public key was not found or request failed
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

    QString publicKey = this->fetch_local_public_key();

    if (publicKey.isEmpty()){
        // Clear data on failure to get public key
        this->otherPublicKey.clear();
        return;
    }

    QString hash = this->generate_hash(publicKey);

    if (hash.isEmpty()){
        QMessageBox::warning(this, "Error", "Could not generate hash");
        // Clear data on failure to generate hash
        this->otherPublicKey.clear();
        return;
    }

    this->ui->displayLineEdit->setText(hash);

    toggleUIElements(true); // Show the UI elements for acceptance/rejection
}

void VerifyPage::on_rejectButton_clicked() {
    setButtonsEnabled(false);
    QMessageBox::information(this, "Rejected", "Friendship rejected!");
    switchPages(FIND_FRIEND_INDEX);
}

void VerifyPage::on_acceptButton_clicked() {
    // TODO: Implement the logic to accept the friendship and store it locally
    setButtonsEnabled(false);
    QMessageBox::information(this, "Success", "Friendship accepted!");
    
    emit goToMainMenuRequested(); 
    // internal switch to the find friend page
    switchPages(FIND_FRIEND_INDEX);
}

bool VerifyPage::validateUsername(const QString& username) {
    // Check if the username is empty
    if (username.trimmed().isEmpty()) {
        QMessageBox::warning(this, "Validation Error", "Username cannot be empty.");
        return false;
    }

    // Ensure username has the same validation as the one used in the registration page
    if (RESTRICTED_CHARS_REGEX.match(username).hasMatch()) {
        QMessageBox::warning(this, "Error", 
            "Username contains invalid characters. Please use only letters, numbers, underscores, and hyphens.");
        return false;
    }

    return true;
}


void VerifyPage::toggleUIElements(bool show) {
    if (show){
        this->ui->acceptButton->show();
        this->ui->rejectButton->show();
        this->ui->acceptanceInfoLabel->show();
    } else {
        this->ui->displayLineEdit->clear(); 
        this->ui->usernameLineEdit->clear();
        this->ui->acceptButton->hide();
        this->ui->rejectButton->hide();
        this->ui->acceptanceInfoLabel->hide();
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
        this->otherPublicKey.clear();  
        toggleUIElements(false); // Hide all UI elements
    }
    setButtonsEnabled(true);
}

VerifyPage::~VerifyPage()
{
    qDebug() << "Destroying Verify Page";
    delete this->ui;

}


void VerifyPage::on_findButton_clicked()
{
   QString username = this->ui->usernameLineEdit->text();
    if (validateUsername(username)) {
        this->ui->usernameLineEdit->clear(); 


        if (fetch_server_public_key(username)) {
              switchPages(VERIFY_PUBLIC_KEY_INDEX);
        }
        // Error messages are handled in fetch_server_public_key, so no need to show them here
    }
    // Error messages are handled in validateUsername, so no need to show them here
}

