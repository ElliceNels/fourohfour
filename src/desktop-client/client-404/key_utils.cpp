#include "key_utils.h"
#include "qjsondocument.h"
#include "qjsonobject.h"
#include <sodium.h>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <sodium.h>
#include <QByteArray>
#include <QString>

bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64) {
    if (sodium_init() < 0) {
        // libsodium couldn't be initialized
        return false;
    }

    unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char privateKey[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(publicKey, privateKey);

    QByteArray pubKeyArray(reinterpret_cast<char*>(publicKey), crypto_box_PUBLICKEYBYTES);
    QByteArray privKeyArray(reinterpret_cast<char*>(privateKey), crypto_box_SECRETKEYBYTES);

    publicKeyBase64 = pubKeyArray.toBase64();
    privateKeyBase64 = privKeyArray.toBase64();

    return true;
}

bool saveKeysToJsonFile(QWidget *parent, const QString &publicKey, const QString &privateKey, const QString &defaultName) {
    QJsonObject json;
    json["publicKey"] = publicKey;
    json["privateKey"] = privateKey;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson();

    QString fileName = QFileDialog::getSaveFileName(parent, "Save Keys", defaultName, "JSON Files (*.json);;All Files (*)");
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            file.write(jsonData);
            file.close();
            return true;
        } else {
            QMessageBox::warning(parent, "Error", "Failed to open file for writing.");
        }
    }
    return false;
}

QString generateSalt(size_t length){
    const size_t SALT_LENGTH = length;
    unsigned char salt[SALT_LENGTH];
    randombytes_buf(salt, SALT_LENGTH);

    // Convert to QString
    QByteArray saltArray(reinterpret_cast<char*>(salt), SALT_LENGTH);
    QString saltBase64 = saltArray.toBase64();
    return saltBase64;
}
