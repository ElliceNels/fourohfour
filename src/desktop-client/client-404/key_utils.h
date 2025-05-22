#ifndef KEY_UTILS_H
#define KEY_UTILS_H

#include <QString>
#include <QWidget>


bool generateSodiumKeyPair(QString &publicKeyBase64, QString &privateKeyBase64);
bool saveKeyToFile(QWidget *parent, const QString &key, const QString &defaultName);

#endif // KEY_UTILS_H
