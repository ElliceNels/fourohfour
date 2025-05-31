#include "utils/password_utils.h"
#include <sodium.h>
#include <QSet>
#include <QStringList>
#include <QFile>
#include <QTextStream>
using namespace std;

bool hash_password(const string& password, string& hashed) {
    char hash_buf[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(
            hash_buf, password.c_str(), password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        return false; // out of memory
    }
    hashed = hash_buf;
    return true;
}

string verify_password(const string& hashed, const string& password) {
    if (crypto_pwhash_str_verify(hashed.c_str(), password.c_str(), password.size()) == 0){
        return "Verification successful";
    } else{
        return "Failed verification";
    }
}

bool deterministic_hash_password(const string& password, const string& salt, string& hashed) {
    // Define a reasonable output length for the hash (e.g., 32 bytes)
    const size_t hash_len = 32;  // or any other length you prefer
    unsigned char hash[hash_len];

    if (crypto_pwhash(
            hash, hash_len,  // Use our defined length
            password.c_str(), password.size(),
            (const unsigned char*)salt.c_str(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_DEFAULT) != 0) {
        return false; // out of memory
    }

    // Convert the hash to a string (you might want to use base64 or hex encoding)
    hashed = string(reinterpret_cast<char*>(hash), hash_len);
    return true;
}


QSet<QString> loadDictionaryWords(const QString& filePath) {
    QSet<QString> words;
    QFile file(filePath);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);
        while (!in.atEnd()) {
            QString line = in.readLine().trimmed().toLower();
            if (!line.isEmpty())
                words.insert(line);
        }
        file.close();
    }
    return words;
}
