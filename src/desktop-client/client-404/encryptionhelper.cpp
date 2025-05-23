#include "encryptionhelper.h"
#include <stdexcept>
#include <vector>

using namespace std;

EncryptionHelper::EncryptionHelper() {
    if (sodium_init() < 0) {
        throw runtime_error("Failed to initialize libsodium");
    }
}

void EncryptionHelper::generateKey(unsigned char* key, size_t key_buffer_size) {
    if (key == nullptr) {
        throw invalid_argument("Key buffer cannot be null");
    }
    if (key_buffer_size < crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw invalid_argument("Key buffer too small");
    }
    crypto_aead_xchacha20poly1305_ietf_keygen(key);
}

void EncryptionHelper::generateNonce(unsigned char* nonce, size_t nonce_buffer_size) {
    if (nonce == nullptr) {
        throw invalid_argument("Nonce buffer cannot be null");
    }
    if (nonce_buffer_size < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        throw invalid_argument("Nonce buffer too small");
    }
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

vector<unsigned char> EncryptionHelper::encrypt(
    const unsigned char* plaintext, unsigned long long plaintext_len,
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* additional_data,
    unsigned long long ad_len
    ) {
    vector<unsigned char> ciphertext(plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    int ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(),
        &ciphertext_len,
        plaintext,
        plaintext_len,
        additional_data,
        ad_len,
        nullptr, // secret nonce parameter not used
        nonce,
        key
        );

    if (ret != 0) {
        throw runtime_error("Encryption failed");
    }

    // Because we allocate more space than needed, we trim to the size of the actual ciphertext
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

vector<unsigned char> EncryptionHelper::decrypt(
    const unsigned char* ciphertext, unsigned long long ciphertext_len,
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* additional_data,
    unsigned long long ad_len
    ) {
    if (ciphertext_len < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw runtime_error("Ciphertext too short");
    }

    vector<unsigned char> plaintext(ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;

    int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(),
        &plaintext_len,
        nullptr, // secret nonce parameter not used
        ciphertext,
        ciphertext_len,
        additional_data,
        ad_len,
        nonce,
        key
        );

    if (ret != 0) {
        throw runtime_error("Decryption failed or message forged");
    }

    // Because we allocate more space than needed, we trim to the size of the actual plaintext
    plaintext.resize(plaintext_len);
    return plaintext;
}
