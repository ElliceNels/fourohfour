#include "key_utils.h"
#include <sodium.h>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>

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

bool saveKeyToFile(QWidget *parent, const QString &key, const QString &defaultName) {
    QString fileName = QFileDialog::getSaveFileName(parent, "Save Key", defaultName, "Text Files (*.txt);;All Files (*)");
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            file.write(key.toUtf8());
            file.close();
            return true;
        } else {
            QMessageBox::warning(parent, "Error", "Failed to open file for writing.");
        }
    }
    return false;
}
