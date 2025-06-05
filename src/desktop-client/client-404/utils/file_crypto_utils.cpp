#include "utils/file_crypto_utils.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QMessageBox>
#include "constants.h"
#include "crypto/encryptionhelper.h"
#include "core/loginsessionmanager.h"
#include "utils/securebufferutils.h"

// Format file metadata for encryption/decryption
QByteArray FileCryptoUtils::formatFileMetadata(const QString &fileName, 
                                              const QString &fileType, 
                                              qint64 fileSize) {
    QJsonObject fileMetaData;
    fileMetaData["fileName"] = fileName;
    fileMetaData["fileType"] = fileType;
    fileMetaData["fileSize"] = static_cast<double>(fileSize); 

    QJsonDocument metadataDoc(fileMetaData);
    return metadataDoc.toJson(QJsonDocument::Compact);
}

// Build the key storage file path for the current user
QString FileCryptoUtils::buildKeyStorageFilePath() {
    const QString username = LoginSessionManager::getInstance().getUsername();
    return QCoreApplication::applicationDirPath() + keysPath + username + binaryExtension;
}

// Validate key parameters 
bool FileCryptoUtils::validateKeyParameters(const unsigned char *key, size_t keyLen, QWidget* parentWidget) {
    if (key == nullptr || keyLen != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Error",
                QString("Invalid file encryption key length: expected %1 bytes, got %2 bytes")
                    .arg(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
                    .arg(keyLen));
        }
        return false;
    }
    return true;
}

// Validate master key
bool FileCryptoUtils::validateMasterKey(const SecureVector &masterKey,  QWidget* parentWidget) {
    if (masterKey.empty() || masterKey.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Error",
                QString("Invalid master key length: expected %1 bytes, got %2 bytes")
                    .arg(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
                    .arg(masterKey.size()));
        }
        return false;
    }
    return true;
}

// Read and decrypt the key storage file
bool FileCryptoUtils::readAndDecryptKeyStorage(const QString &filepath, const SecureVector &masterKey, QByteArray &jsonData, QWidget* parentWidget) {
    // Check if file exists
    if (!QFile::exists(filepath)) {
        if (parentWidget) {
            QMessageBox::information(parentWidget, "Initialization", "Encrypted keys file not found. Initializing empty key storage.");
        }
        jsonData = QByteArray("{}"); // Initialize empty JSON object
        return true;
    }

    // Read file data
    QFile file(filepath);
    if (!file.open(QIODevice::ReadOnly)) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Decryption Error", 
                "Failed to open encrypted keys file: " + file.errorString());
        }
        return false;
    }
    const QByteArray fileData = file.readAll();
    file.close();

    // Validate data size
    const int ciphertextSize = fileData.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (ciphertextSize <= 0) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Decryption Error", "Encrypted file is too small. It may be corrupted.");
        }
        return false;
    }

    // Extract components
    SecureVector ciphertext(ciphertextSize);
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    
    memcpy(nonce.get(), fileData.constData(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    memcpy(ciphertext.data(), fileData.constData() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, ciphertextSize);

    // Decrypt data
    EncryptionHelper crypto;
    SecureVector plaintext;
    try {
        plaintext = crypto.decrypt(
            ciphertext.data(),
            ciphertextSize,
            masterKey.data(),
            nonce.get(),
            nullptr,
            0
        );
        
        jsonData = QByteArray(reinterpret_cast<const char*>(plaintext.data()), static_cast<int>(plaintext.size()));
        
        return true;
    } catch (const std::exception& e) {
        if (parentWidget) {
            QMessageBox::critical(parentWidget, "Decryption Error", 
                QString("Decryption failed: %1").arg(e.what()));
        }
        return false;
    }
}

// Add a key to the JSON storage
bool FileCryptoUtils::addKeyToJsonStorage(const QByteArray &jsonData, const QString &fileUuid, const unsigned char *key, size_t keyLen, QByteArray &updatedJsonData, QWidget* parentWidget) {
    // Parse JSON
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Error",
                QString("Failed to parse JSON: %1").arg(parseError.errorString()));
        }
        return false;
    }

    // Update JSON structure
    QJsonObject json = doc.isObject() ? doc.object() : QJsonObject();
    QJsonObject filesObject = json.contains("files") ? json["files"].toObject() : QJsonObject();
    
    // Convert key to base64
    QByteArray keyBytes(reinterpret_cast<const char*>(key), keyLen);
    filesObject[fileUuid] = QString(keyBytes.toBase64());
    
    json["files"] = filesObject;
    doc.setObject(json);
    
    // Convert back to bytes
    updatedJsonData = doc.toJson(QJsonDocument::Compact);
    return true;
}

// Encrypt and save the updated key storage
bool FileCryptoUtils::encryptAndSaveKeyStorage(const QString &filepath, const QByteArray &jsonData, const SecureVector &masterKey, QWidget* parentWidget) {
    EncryptionHelper crypto;
    auto nonce = make_secure_buffer<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    crypto.generateNonce(nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    
    // Encrypt data
    SecureVector ciphertext = crypto.encrypt(
        reinterpret_cast<const unsigned char*>(jsonData.constData()),
        jsonData.size(),
        masterKey.data(),
        nonce.get(),
        nullptr,
        0
    );
    
    // Prepare data for saving: [nonce][ciphertext]
    SecureVector combinedData(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + ciphertext.size());

    memcpy(combinedData.data(), nonce.get(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    memcpy(combinedData.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 
           ciphertext.data(), ciphertext.size());
    
    // Save file
    QFile file(filepath);
    if (!file.open(QIODevice::WriteOnly)) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Encryption Error", 
                "Failed to open file for writing: " + file.errorString());
        }
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(combinedData.data()), 
              static_cast<qint64>(combinedData.size()));
    file.close();
    qDebug() << "Key storage updated and saved successfully";
    return true;
}

// Save file encryption key to local storage
bool FileCryptoUtils::saveKeyToLocalStorage(const QString &fileUuid, const unsigned char *key, size_t keyLen, QWidget* parentWidget) {
    // Validate inputs
    if (!validateKeyParameters(key, keyLen, parentWidget)) {
        return false;
    }

    // Get master key and validate it
    const SecureVector masterKey = LoginSessionManager::getInstance().getMasterKey();
    if (!validateMasterKey(masterKey, parentWidget)) {
        return false;
    }

    // Get file path for user's key storage
    const QString filepath = buildKeyStorageFilePath();
    
    // Read and decrypt key storage file
    QByteArray jsonData;
    if (!readAndDecryptKeyStorage(filepath, masterKey, jsonData, parentWidget)) {
        return false;
    }
    
    // Update JSON with new key
    QByteArray updatedJsonData;
    if (!addKeyToJsonStorage(jsonData, fileUuid, key, keyLen, updatedJsonData, parentWidget)) {
        return false;
    }
    
    // Encrypt and save updated storage
    return encryptAndSaveKeyStorage(filepath, updatedJsonData, masterKey, parentWidget);
}

// Get file encryption key from storage
bool FileCryptoUtils::getFileEncryptionKey(const QString &fileUuid, unsigned char *key, size_t keyLen, QWidget* parentWidget) {
    if (!validateKeyParameters(key, keyLen, parentWidget)) {
        return false;
    }

    // Get master key and validate it
    const SecureVector masterKey = LoginSessionManager::getInstance().getMasterKey();
    if (!validateMasterKey(masterKey, parentWidget)) {
        return false;
    }

    // Get file path for user's key storage
    const QString filepath = buildKeyStorageFilePath();
    
    // Read and decrypt key storage file
    QByteArray jsonData;
    if (!readAndDecryptKeyStorage(filepath, masterKey, jsonData, parentWidget)) {
        return false;
    }
    
    // Parse JSON
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(jsonData, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Error",
                QString("Failed to parse JSON: %1").arg(parseError.errorString()));
        }
        return false;
    }

    // Find the key for this file
    QJsonObject json = doc.object();
    if (!json.contains("files")) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Error", "Invalid key storage format");
        }
        return false;
    }
    
    QJsonObject filesObject = json["files"].toObject();
    if (!filesObject.contains(fileUuid)) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Error", 
                QString("No decryption key found for file: %1").arg(fileUuid));
        }
        return false;
    }
    
    // Extract the file key
    QByteArray fileKeyData = QByteArray::fromBase64(filesObject[fileUuid].toString().toLatin1());
    if (fileKeyData.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        if (parentWidget) {
            QMessageBox::warning(parentWidget, "Error", 
                QString("Invalid key length for file: %1").arg(fileUuid));
        }
        return false;
    }
    
    // Copy the key to the provided buffer
    memcpy(key, fileKeyData.constData(), keyLen);
    return true;
}
