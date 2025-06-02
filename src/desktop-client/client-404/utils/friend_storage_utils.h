#ifndef FRIEND_STORAGE_UTILS_H
#define FRIEND_STORAGE_UTILS_H

#include <QString>
#include <QJsonObject>
#include <QWidget>

class FriendStorageUtils {
public:
    static QString buildFriendStorageFilePath(const QString& username);
    static QJsonObject readFriendsJson(const QString& filepath, QWidget* parent = nullptr);
    static bool writeFriendsJson(const QString& filepath, const QJsonObject& friendsData, QWidget* parent = nullptr);
    static bool saveFriendPairToJSON(const QString& username, const QString& publicKey, QWidget* parent = nullptr);
};

#endif // FRIEND_STORAGE_UTILS_H
