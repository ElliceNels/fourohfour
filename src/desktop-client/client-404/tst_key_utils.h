#ifndef TST_KEY_UTILS_H
#define TST_KEY_UTILS_H

#include <QTest>
#include <QObject>
#include "key_utils.h"
#include "securevector.h"
#include "encryptionhelper.h"

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
};

#endif // TST_KEY_UTILS_H
