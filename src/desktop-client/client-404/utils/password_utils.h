#ifndef PASSWORD_UTILS_H
#define PASSWORD_UTILS_H
#include <QSet>
#include <QStringList>

#include <string>

bool hash_password(const std::string& password, std::string& hashed);
bool deterministic_hash_password(const std::string& password, const std::string& salt, std::string& hashed);
std::string verify_password(const std::string& hashed, const std::string& password);
QSet<QString> loadDictionaryWords(const QString& filePath);

#endif // PASSWORD_UTILS_H
