#include "json_sanitizer.h"
#include <QJsonDocument>
#include <QByteArray>

// Initialize static member with specific sensitive fields from the routes
QStringList JsonSanitizer::s_sensitiveFields = {
    // From authentication routes
    "password",
    "hashed_password", 
    "access_token", 
    "refresh_token",
    "public_key",
    "salt",
    "new_password",
    
    // From file routes
    "encrypted_file",
    "encrypted_keys",
    
    // From permission routes
    "key_for_recipient"
};

QJsonDocument JsonSanitizer::sanitizeJson(const QJsonDocument& jsonDoc) {
    if (jsonDoc.isNull() || jsonDoc.isEmpty())
        return jsonDoc;
    
    if (jsonDoc.isObject()) {
        QJsonObject sanitized = jsonDoc.object();
        
        for (const auto& field : s_sensitiveFields) {
            if (sanitized.contains(field)) {
                sanitized[field] = "[REDACTED]";
            }
        }
        return QJsonDocument(sanitized);
    }
    
    return jsonDoc;
}

string JsonSanitizer::sanitizeJsonString(const string& jsonStr) {
    if (jsonStr.empty())
        return jsonStr;
    
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(jsonStr));
    if (doc.isNull())
        return jsonStr; // Not valid JSON, return as is
        
    return sanitizeJson(doc).toJson(QJsonDocument::Compact).toStdString();
}
