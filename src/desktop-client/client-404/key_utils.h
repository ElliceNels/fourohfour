#ifndef KEY_UTILS_H
#define KEY_UTILS_H

#include <QString>
#include <QWidget>


bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64);
bool saveKeysToJsonFile(QWidget *parent, const QString &publicKey, const QString &privateKey, const QString &defaultName);
bool encryptAndSaveKey(QWidget *parent, const QString &privateKey);
QString generateSalt(size_t length);

#endif // KEY_UTILS_H
