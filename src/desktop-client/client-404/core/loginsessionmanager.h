#ifndef LOGINSESSIONMANAGER_H
#define LOGINSESSIONMANAGER_H

#include <QString>
#include "utils/securevector.h"
#include "utils/request_utils.h"

class LoginSessionManager {

public:
    static LoginSessionManager& getInstance();

    void setSession(const QString& username, const unsigned char* masterKey, size_t keyLength);
    const QString getUsername() const;
    const SecureVector getMasterKey() const;
    void setTokens(const QString& accessToken, const QString& refreshToken);
    void setBaseUrl(const QString& baseUrl);

    // HTTP methods
    RequestUtils::Response post(const std::string& url, const QJsonObject& data = QJsonObject());
    RequestUtils::Response get(const std::string& url, const QJsonObject& data = QJsonObject());
    RequestUtils::Response del(const std::string& url, const QJsonObject& data = QJsonObject());
    
    void clearSession();

private:
    LoginSessionManager();  // private constructor
    ~LoginSessionManager();

    LoginSessionManager(const LoginSessionManager&) = delete;            // Disable copy constructor: you cannot create a new instance by copying an existing one.
    LoginSessionManager& operator=(const LoginSessionManager&) = delete; // Disable copy assignment: you cannot assign one instance to another via copying.
    LoginSessionManager(LoginSessionManager&&) = delete;                 // Disable move constructor: you cannot move-construct an instance from another.
    LoginSessionManager& operator=(LoginSessionManager&&) = delete;      // Disable move assignment: you cannot move-assign one instance to another.

    QString m_username;
    SecureVector m_masterKey;
    RequestUtils m_requestUtils;
};

#endif
