#include "verifypage.h"
#include "pages.h"
#include "ui_verifypage.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <qstackedwidget.h>
#include <sodium.h>

VerifyPage::VerifyPage(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::VerifyPage)
    ,otherPublicKey(nullptr)
{
    ui->setupUi(this);
    if (sodium_init() < 0) {
        QMessageBox::critical(this, "Error", "Failed to initialize libsodium");
    }
}

VerifyPage::~VerifyPage()
{
    delete ui;
    delete otherPublicKey;  // clean up pointer to avoid memory leak
}

void VerifyPage::set_other_public_key(const QByteArray &otherpk){
    if (otherPublicKey != nullptr) {
        delete otherPublicKey;  // delete old value to avoid leak
    }
    otherPublicKey = new QByteArray(otherpk);
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
    if (usersPublicKey.isEmpty() || otherPublicKey == nullptr || otherPublicKey->isEmpty()) {
        return QString();
    }

    QByteArray encodedUserPK = usersPublicKey.toUtf8();

    // Ensures there is a consistent order of concatenation cross device
    QByteArray concatenated;
    if (encodedUserPK < (*this->otherPublicKey)) {
        concatenated = encodedUserPK + (*this->otherPublicKey);
    } else {
        concatenated = (*this->otherPublicKey) + encodedUserPK;
    }

    // Hash the combination of keys
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, reinterpret_cast<const unsigned char*>(concatenated.constData()), concatenated.size());

    // Convert the hash into a readable form to display on the ui
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

    QString publicKey = fetch_public_key();

    if (publicKey.isEmpty()){
        QMessageBox::warning(this, "Error", "Could not retrieve public key");
        return;
    }

    QString hash = generate_hash(publicKey);

    if (hash.isEmpty()){
        QMessageBox::warning(this, "Error", "Could not generate hash");
        return;
    }

    this->ui->displayLineEdit->setText(hash);
}

void VerifyPage::on_backButton_clicked()
{
    // Switch to main menu after login
    QStackedWidget *stack = qobject_cast<QStackedWidget *>(this->parentWidget());
    if (stack) {
        stack->setCurrentIndex(Pages::MainMenuIndex);
    }
}

