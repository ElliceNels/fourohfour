// LoginSessionManager.cpp
#include "LoginSessionManager.h"
#include <qdebug.h>
#include <sodium.h>
#include <cstring>
#include <QString>

LoginSessionManager::LoginSessionManager()
    : m_masterKey(nullptr), m_keyLength(0) {}

LoginSessionManager::~LoginSessionManager() {
    clearSession();
    qDebug() << "Session cleaned up through the destructor";
}

LoginSessionManager& LoginSessionManager::getInstance() {
    static LoginSessionManager instance;
    return instance;
}

void LoginSessionManager::setSession(const QString& username, const unsigned char* masterKey, size_t keyLength) {
    clearSession(); // clear old data first just in case

    m_username = username;
    m_keyLength = keyLength;

    // Allocate and copy the key securely
    //If it is swapped out to disk, an attacker with disk access could recover it from the swap file.
    // Locked memory prevents this risk by ensuring the key never touches the disk.

    m_masterKey = static_cast<unsigned char*>(sodium_malloc(keyLength));
    if (m_masterKey) {
        memcpy(m_masterKey, masterKey, keyLength);
    }

}

const QString& LoginSessionManager::getUsername() const {
    return m_username;
}

const unsigned char* LoginSessionManager::getMasterKey() const {
    return m_masterKey;
}

void LoginSessionManager::clearSession() {
    if (m_masterKey) {
        sodium_memzero(m_masterKey, m_keyLength);
        sodium_free(m_masterKey);
        m_masterKey = nullptr;
    }
    m_keyLength = 0;
    m_username.clear();

    qDebug() << "Session cleaned up when called";
}
