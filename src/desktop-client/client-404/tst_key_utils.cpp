#include "tst_key_utils.h"
#include "securebufferutils.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryFile>
#include <QDir>
#include <QFile>
#include <QByteArray>
#include <QRegularExpression>
#include <sodium.h>

void TestKeyUtils::testGenerateSodiumKeyPair()
{
    QString publicKey, privateKey;
    bool result = generateSodiumKeyPair(publicKey, privateKey);

    QVERIFY(result);
    QVERIFY(!publicKey.isEmpty());
    QVERIFY(!privateKey.isEmpty());
    QVERIFY(publicKey != privateKey);
}

void TestKeyUtils::testGenerateSodiumKeyPairLength()
{
    QString publicKey, privateKey;
    generateSodiumKeyPair(publicKey, privateKey);

    // Convert base64 strings back to binary
    QByteArray pubKeyArray = QByteArray::fromBase64(publicKey.toUtf8());
    QByteArray privKeyArray = QByteArray::fromBase64(privateKey.toUtf8());

    // Verify lengths match sodium's expected sizes
    QCOMPARE(pubKeyArray.size(), static_cast<int>(crypto_box_PUBLICKEYBYTES));
    QCOMPARE(privKeyArray.size(), static_cast<int>(crypto_box_SECRETKEYBYTES));
}

void TestKeyUtils::testGenerateSodiumKeyPairFormat()
{
    QString publicKey, privateKey;
    generateSodiumKeyPair(publicKey, privateKey);

    // Verify base64 format using QRegularExpression
    QRegularExpression base64Pattern("^[A-Za-z0-9+/]+={0,2}$");
    QVERIFY(base64Pattern.match(publicKey).hasMatch());
    QVERIFY(base64Pattern.match(privateKey).hasMatch());
}



void TestKeyUtils::testEncryptData()
{
    // Create test data
    QByteArray plaintext = "Test encryption data";
    auto key = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();

    // Initialize sodium
    if (sodium_init() < 0) {
        QFAIL("Failed to initialize sodium");
    }

    // Generate random key and nonce
    randombytes_buf(key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Create encryption helper
    auto crypto = std::make_shared<EncryptionHelper>();

    // Encrypt data
    SecureVector ciphertext = encryptData(plaintext, key.get(), nonce.get(), crypto);

    // Verify encryption
    QVERIFY(ciphertext.size() > 0);
    QVERIFY(ciphertext.size() > plaintext.size()); // Ciphertext should be larger due to auth tag
}

void TestKeyUtils::testEncryptDataEmptyInput()
{
    QByteArray plaintext;
    auto key = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();

    // Initialize sodium
    if (sodium_init() < 0) {
        QFAIL("Failed to initialize sodium");
    }

    // Generate random key and nonce
    randombytes_buf(key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Create encryption helper
    auto crypto = std::make_shared<EncryptionHelper>();

    // Encrypt empty data
    SecureVector ciphertext = encryptData(plaintext, key.get(), nonce.get(), crypto);

    // Verify encryption of empty data
    QVERIFY(ciphertext.size() > 0);
    QVERIFY(ciphertext.size() >= crypto_aead_xchacha20poly1305_ietf_ABYTES); // Should at least contain auth tag
}

void TestKeyUtils::testEncryptDataLargeInput()
{
    // Create large test data (1MB)
    QByteArray plaintext(1024 * 1024, 'A');
    auto key = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>();
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();

    // Initialize sodium
    if (sodium_init() < 0) {
        QFAIL("Failed to initialize sodium");
    }

    // Generate random key and nonce
    randombytes_buf(key.get(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Create encryption helper
    auto crypto = std::make_shared<EncryptionHelper>();

    // Encrypt large data
    SecureVector ciphertext = encryptData(plaintext, key.get(), nonce.get(), crypto);

    // Verify encryption of large data
    QVERIFY(ciphertext.size() > 0);
    QVERIFY(ciphertext.size() > plaintext.size());
}

void TestKeyUtils::testSaveFileSecureVector()
{
    // Create test data
    SecureVector data(100);
    std::fill(data.begin(), data.end(), 'A');

    // Create a temporary file
    QTemporaryFile tempFile;
    tempFile.setAutoRemove(false);
    tempFile.open();
    QString tempPath = tempFile.fileName();
    tempFile.close();

    // Save data
    bool result = saveFile(tempPath, data);
    QVERIFY(result);

    // Verify file contents
    QFile file(tempPath);
    QVERIFY(file.open(QIODevice::ReadOnly));
    QByteArray readData = file.readAll();
    QCOMPARE(readData.size(), static_cast<int>(data.size()));

    // Cleanup
    file.close();
    QFile::remove(tempPath);
}

void TestKeyUtils::testGenerateSalt()
{
    // Test default salt generation
    QString salt1 = generateSalt();
    QVERIFY(!salt1.isEmpty());

    // Verify base64 format
    QRegularExpression base64Pattern("^[A-Za-z0-9+/]+={0,2}$");
    QVERIFY(base64Pattern.match(salt1).hasMatch());

    // Verify length (after base64 decoding)
    QByteArray decodedSalt = QByteArray::fromBase64(salt1.toUtf8());
    QCOMPARE(decodedSalt.size(), static_cast<int>(crypto_pwhash_SALTBYTES));

    // Test that two generated salts are different
    QString salt2 = generateSalt();
    QVERIFY(salt1 != salt2);
}

void TestKeyUtils::testGenerateSaltCustomLength()
{
    const size_t customLength = 32;
    QString salt = generateSalt(customLength);

    // Verify base64 format
    QRegularExpression base64Pattern("^[A-Za-z0-9+/]+={0,2}$");
    QVERIFY(base64Pattern.match(salt).hasMatch());

    // Verify length (after base64 decoding)
    QByteArray decodedSalt = QByteArray::fromBase64(salt.toUtf8());
    QCOMPARE(decodedSalt.size(), static_cast<int>(customLength));
}

void TestKeyUtils::testDeriveKeyFromPassword()
{
    // Initialize sodium
    if (sodium_init() < 0) {
        QFAIL("Failed to initialize sodium");
    }

    // Test data
    std::string password = "testPassword123!";
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // Generate random salt
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    // Test key derivation
    bool result = deriveKeyFromPassword(password, salt, key);
    QVERIFY(result);

    // Verify key is not all zeros
    bool allZeros = true;
    for (size_t i = 0; i < crypto_aead_xchacha20poly1305_ietf_KEYBYTES; i++) {
        if (key[i] != 0) {
            allZeros = false;
            break;
        }
    }
    QVERIFY(!allZeros);
}

void TestKeyUtils::testDeriveKeyFromPasswordConsistency()
{
    // Initialize sodium
    if (sodium_init() < 0) {
        QFAIL("Failed to initialize sodium");
    }

    // Test data
    std::string password = "testPassword123!";
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key1[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char key2[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // Generate random salt
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    // Derive key twice with same password and salt
    bool result1 = deriveKeyFromPassword(password, salt, key1);
    bool result2 = deriveKeyFromPassword(password, salt, key2);

    QVERIFY(result1);
    QVERIFY(result2);

    // Verify both keys are identical
    QCOMPARE(memcmp(key1, key2, crypto_aead_xchacha20poly1305_ietf_KEYBYTES), 0);
}

void TestKeyUtils::testDeriveKeyFromPasswordDifferentSalts()
{
    // Initialize sodium
    if (sodium_init() < 0) {
        QFAIL("Failed to initialize sodium");
    }

    // Test data
    std::string password = "testPassword123!";
    unsigned char salt1[crypto_pwhash_SALTBYTES];
    unsigned char salt2[crypto_pwhash_SALTBYTES];
    unsigned char key1[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char key2[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // Generate two different salts
    randombytes_buf(salt1, crypto_pwhash_SALTBYTES);
    randombytes_buf(salt2, crypto_pwhash_SALTBYTES);

    // Derive keys with different salts
    bool result1 = deriveKeyFromPassword(password, salt1, key1);
    bool result2 = deriveKeyFromPassword(password, salt2, key2);

    QVERIFY(result1);
    QVERIFY(result2);

    // Verify keys are different
    QVERIFY(memcmp(key1, key2, crypto_aead_xchacha20poly1305_ietf_KEYBYTES) != 0);
}

void TestKeyUtils::testDeriveKeyFromPasswordEmptyPassword()
{
    // Initialize sodium
    if (sodium_init() < 0) {
        QFAIL("Failed to initialize sodium");
    }

    // Test data
    std::string password = "";
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // Generate random salt
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    // Test key derivation with empty password
    bool result = deriveKeyFromPassword(password, salt, key);
    QVERIFY(result);

    // Verify key is not all zeros
    bool allZeros = true;
    for (size_t i = 0; i < crypto_aead_xchacha20poly1305_ietf_KEYBYTES; i++) {
        if (key[i] != 0) {
            allZeros = false;
            break;
        }
    }
    QVERIFY(!allZeros);
}



QTEST_MAIN(TestKeyUtils)
