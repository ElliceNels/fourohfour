#pragma once

#include <QJsonDocument>
#include <QJsonObject>
#include <QStringList>
#include <string>

using namespace std;

class JsonSanitizer {
public:
    // Sanitize a JSON document by redacting sensitive fields
    static QJsonDocument sanitizeJson(const QJsonDocument& jsonDoc);
    
    // Sanitize a JSON string by parsing and redacting sensitive fields
    static string sanitizeJsonString(const string& jsonStr);
    
private:
    // Default list of sensitive fields to redact
    static QStringList s_sensitiveFields;
};
