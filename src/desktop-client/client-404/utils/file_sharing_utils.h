#ifndef FILE_SHARING_UTILS_H
#define FILE_SHARING_UTILS_H

#include <QVector>
#include <QByteArray>
#include "utils/securevector.h"

class FileSharingUtils {

    public:
        QVector<QByteArray> generateOneTimePreKeyPairs();
    private:
        bool saveOneTimePreKeyPairsLocally(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys);
        
        // Helper methods for key storage
        bool validateKeyPairs(const QVector<QByteArray>& publicKeys, const QVector<QByteArray>& privateKeys);
        bool updateJsonWithPrekeys(const QByteArray &jsonData, 
                                  const QVector<QByteArray>& publicKeys, 
                                  const QVector<QByteArray>& privateKeys,
                                  QByteArray &updatedJsonData);
};

#endif // FILE_SHARING_UTILS_H
