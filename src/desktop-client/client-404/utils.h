#ifndef UTILS_H
#define UTILS_H
#include "qobject.h"

bool sendData(QByteArray jsonData, QObject *parent, QString endpoint);

#endif // UTILS_H
