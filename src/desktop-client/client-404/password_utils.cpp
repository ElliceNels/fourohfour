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


const QSet<QString> DICTIONARY_WORDS = QSet<QString>({
    "password",
    "123456",
    "12345678",
    "abc123",
    "qwerty",
    "monkey",
    "letmein",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "trustno1",
    "1234567",
    "sunshine",
    "master",
    "123123",
    "welcome",
    "shadow",
    "ashley",
    "football",
    "jesus",
    "michael",
    "ninja",
    "mustang",
    "password1"
});


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
