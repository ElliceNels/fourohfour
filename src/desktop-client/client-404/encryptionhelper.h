#ifndef ENCRYPTIONHELPER_H
#define ENCRYPTIONHELPER_H

#include <sodium.h>
#include <vector>

using namespace std;

class EncryptionHelper
{
public:
    EncryptionHelper();
    void generateKey(unsigned char* key, size_t key_buffer_size);
    void generateNonce(unsigned char* nonce, size_t nonce_buffer_size);
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
