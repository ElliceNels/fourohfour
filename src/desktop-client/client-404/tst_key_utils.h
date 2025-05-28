#ifndef TST_KEY_UTILS_H
#define TST_KEY_UTILS_H

#include <QTest>
#include <QObject>
#include "key_utils.h"
#include "securevector.h"
#include "encryptionhelper.h"
#include <QTemporaryFile>
#include <QDir>
#include <QFile>
#include <QByteArray>
#include <QRegularExpression>
#include <sodium.h>

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

    // Test cases for saveFile
    void testSaveFileSecureVector();

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
