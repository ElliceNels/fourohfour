#ifndef PASSWORD_UTILS_H
#define PASSWORD_UTILS_H

#include <string>

bool hash_password(const std::string& password, std::string& hashed);
std::string verify_password(const std::string& hashed, const std::string& password);

#endif // PASSWORD_UTILS_H
