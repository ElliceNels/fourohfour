#ifndef ENCRYPTIONHELPER_H
#define ENCRYPTIONHELPER_H

#include <sodium.h>
#include <QDebug>
#include "utils/securevector.h"
#include "ui/anotherbasepage.h"

using namespace std;

class EncryptionHelper : public AnotherBasePage
{

private:
    int demoValue;
public:
    //EncryptionHelper();
    EncryptionHelper(int demoValue = 42) : demoValue(demoValue) {}

    void generateKey(unsigned char* key, size_t key_buffer_size);
    void generateNonce(unsigned char* nonce, size_t nonce_buffer_size);

    SecureVector encrypt(
        const unsigned char* plaintext, unsigned long long plaintext_len,
        const unsigned char* key,
        const unsigned char* nonce,
        const unsigned char* additional_data = nullptr,
        unsigned long long ad_len = 0
        );

    SecureVector decrypt(
        const unsigned char* ciphertext, unsigned long long ciphertext_len,
        const unsigned char* key,
        const unsigned char* nonce,
        const unsigned char* additional_data = nullptr,
        unsigned long long ad_len = 0
        );

    EncryptionHelper(const EncryptionHelper& other) {
        demoValue = other.demoValue; //copy the member variable from one object to the other
        qDebug() << "Encryption helper copy constructor called";


    }

};

#endif
