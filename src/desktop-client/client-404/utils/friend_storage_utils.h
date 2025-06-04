#ifndef FRIEND_STORAGE_UTILS_H
#define FRIEND_STORAGE_UTILS_H

#include <QString>
#include <QJsonObject>
#include <QWidget>
#include <QMap>

class FriendStorageUtils {
public:
    static bool saveFriendPairToJSON(const QString& username, const QString& publicKey, QWidget* parent = nullptr);
    static QString getUserPublicKey(const QString& username, QWidget* parent = nullptr);
    static QMap<QString, QString> getAllFriendsExceptSelf(QWidget* parent = nullptr);
    static bool removeFriend(const QString& friendUsername, QWidget* parent = nullptr);
    
private:
    static QString buildFriendStorageFilePath(const QString& username);
    static QJsonObject readFriendsJson(const QString& username, QWidget* parent = nullptr);
    static bool writeFriendsJson(const QString& username, const QJsonObject& friendsData, QWidget* parent = nullptr);
};

#endif // FRIEND_STORAGE_UTILS_H
