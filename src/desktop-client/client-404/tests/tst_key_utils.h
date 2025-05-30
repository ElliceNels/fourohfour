#ifndef TST_KEY_UTILS_H
#define TST_KEY_UTILS_H

#include <QTest>
#include <QObject>
#include <QTemporaryFile>
#include <QDir>
#include <QFile>
#include <QByteArray>
#include <QRegularExpression>
#include <sodium.h>
#include "crypto/key_utils.h"
#include "utils/securevector.h"
#include "crypto/encryptionhelper.h"

class TestKeyUtils : public QObject
{
    Q_OBJECT

private slots:
    // Test cases for generateSodiumKeyPair
    void testGenerateSodiumKeyPair();
    void testGenerateSodiumKeyPairLength();
    void testGenerateSodiumKeyPairFormat();

    // Test cases for encryptData
    void testEncryptData();
    void testEncryptDataEmptyInput();
    void testEncryptDataLargeInput();
    void testEncryptAndDecryptData();

    //Test cases for salt
    void testGenerateSalt();
    void testGenerateSaltCustomLength();

    //Test cases for key derivation
    void testDeriveKeyFromPassword();
    void testDeriveKeyFromPasswordConsistency();
    void testDeriveKeyFromPasswordDifferentSalts();
    void testDeriveKeyFromPasswordEmptyPassword();
};

#endif // TST_KEY_UTILS_H
