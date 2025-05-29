#include "constants.h"
#include "qeventloop.h"
#include "qnetworkaccessmanager.h"
#include "qnetworkreply.h"
#include <iostream>
using namespace std;
string sendData(QByteArray jsonData, QObject *parent, QString endpoint)
{
    QNetworkAccessManager manager(parent);
    QNetworkRequest request((QUrl(endpoint)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = manager.post(request, jsonData);

    // Block until finished
    QEventLoop loop;
    QAbstractSocket::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    string ret;
    if (reply->error() == QNetworkReply::NoError) {
        QByteArray response = reply->readAll();
        cout << "server response:" << response.toStdString() << endl;
        ret = response.toStdString();
    } else {
        cout << "server error: " << reply->errorString().toStdString() << endl;
        ret = "ERROR";
    }
    reply->deleteLater();
    return ret;
}
