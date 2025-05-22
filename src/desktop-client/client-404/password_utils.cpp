#include "password_utils.h"
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
