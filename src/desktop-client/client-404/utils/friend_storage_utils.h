#ifndef FRIEND_STORAGE_UTILS_H
#define FRIEND_STORAGE_UTILS_H

#include <QString>
#include <QJsonObject>
#include <QWidget>

class FriendStorageUtils {
public:
    static bool saveFriendPairToJSON(const QString& username, const QString& publicKey, QWidget* parent = nullptr);
private:
    static QString buildFriendStorageFilePath(const QString& username);
    static QJsonObject readFriendsJson(const QString& username, QWidget* parent = nullptr);
    static bool writeFriendsJson(const QString& username, const QJsonObject& friendsData, QWidget* parent = nullptr);
};

#endif // FRIEND_STORAGE_UTILS_H
