#ifndef ENCRYPTIONHELPER_H
#define ENCRYPTIONHELPER_H

#include <sodium.h>
#include <vector>
#include <stdexcept>

using namespace std;

class EncryptionHelper
{
public:
    EncryptionHelper();
    void generateKey(unsigned char* key);
    void generateNonce(unsigned char* nonce);
    vector<unsigned char> encrypt(
        const unsigned char* plaintext, unsigned long long plaintext_len,
        const unsigned char* key,
        const unsigned char* nonce,
        const unsigned char* additional_data = nullptr,
        unsigned long long ad_len = 0
        );
    vector<unsigned char> decrypt(
        const unsigned char* ciphertext, unsigned long long ciphertext_len,
        const unsigned char* key,
        const unsigned char* nonce,
        const unsigned char* additional_data = nullptr,
        unsigned long long ad_len = 0
        );
};

#endif
