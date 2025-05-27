#include "LoginSessionManager.h"
#include <qdebug.h>
#include <sodium.h>
#include <cstring>
#include <QString>

LoginSessionManager::LoginSessionManager()
    : m_masterKey(nullptr), m_keyLength(0) {}

LoginSessionManager::~LoginSessionManager() {
    this->clearSession();
    qDebug() << "Session cleaned up through the destructor";
}

LoginSessionManager& LoginSessionManager::getInstance() {
    static LoginSessionManager instance;
    return instance;
}

void LoginSessionManager::setSession(const QString& username, const unsigned char* masterKey, size_t keyLength) {
    this->clearSession(); // clear old data first just in case

    this->m_username = username;
    this->m_keyLength = keyLength;

    // Allocate and copy the key securely
    this->m_masterKey = static_cast<unsigned char*>(sodium_malloc(keyLength));
    if (this->m_masterKey) {
        memcpy(this->m_masterKey, masterKey, keyLength);
    }
}

const QString& LoginSessionManager::getUsername() const {
    return this->m_username;
}

const unsigned char* LoginSessionManager::getMasterKey() const {
    return this->m_masterKey;
}

void LoginSessionManager::clearSession() {
    if (this->m_masterKey) {
        sodium_memzero(this->m_masterKey, this->m_keyLength);
        sodium_free(this->m_masterKey);
        this->m_masterKey = nullptr;
    }
    this->m_keyLength = 0;
    this->m_username.clear();

    qDebug() << "Session cleaned up when called";
}
