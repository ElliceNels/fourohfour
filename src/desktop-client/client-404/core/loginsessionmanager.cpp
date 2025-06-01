#include "core/loginsessionmanager.h"
#include <qdebug.h>
#include <sodium.h>
#include <cstring>
#include <QString>
#include "utils/securevector.h"
#include "utils/request_utils.h"

LoginSessionManager::LoginSessionManager() {}

LoginSessionManager::~LoginSessionManager() {
    this->clearSession();
    qDebug() << "Session cleaned up through the destructor";
}

LoginSessionManager& LoginSessionManager::getInstance() {
    static LoginSessionManager instance;
    return instance;
}

void LoginSessionManager::setSession(const QString& username, const unsigned char* masterKey, size_t keyLength) {
    this->clearSession();
    this->m_username = username;
    
    // Create new SecureVector and copy the key
    this->m_masterKey = SecureVector(keyLength);
    std::copy(masterKey, masterKey + keyLength, m_masterKey.begin());
}


const QString LoginSessionManager::getUsername() const {
    return this->m_username;
}

const SecureVector LoginSessionManager::getMasterKey() const {
    return SecureVector(this->m_masterKey);  // Return a SecureVector containing the master key
}

void LoginSessionManager::setTokens(const QString& accessToken, const QString& refreshToken) {
    this->m_requestUtils.setBearerToken(accessToken.toStdString());
    this->m_requestUtils.setRefreshToken(refreshToken.toStdString());
}

void LoginSessionManager::setBaseUrl(const QString& baseUrl) {
    this->m_requestUtils.setBaseUrl(baseUrl.toStdString());
}

RequestUtils::Response LoginSessionManager::post(const std::string& url, const QJsonObject& data) {
    return this->m_requestUtils.post(url, data);
}
RequestUtils::Response LoginSessionManager::get(const string& url, const QJsonObject& params){
    return this->m_requestUtils.get(url, params);
}

RequestUtils::Response LoginSessionManager::get(const std::string& url, const QJsonObject& data) {
    return this->m_requestUtils.get(url, data);
}

void LoginSessionManager::clearSession() {
    this->m_masterKey.clear();  // SecureVector handles secure zeroing
    this->m_username.clear();

    qDebug() << "Session cleaned up when called";
}
