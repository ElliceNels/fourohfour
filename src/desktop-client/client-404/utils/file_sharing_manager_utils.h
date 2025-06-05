#ifndef FILE_SHARING_MANAGER_UTILS_H
#define FILE_SHARING_MANAGER_UTILS_H

#include <QString>
#include <QWidget>
#include <QByteArray>

/**
 * @brief Manages the complete file sharing workflow through X3DH protocol
 * 
 * This class provides high-level methods that combine various lower-level utilities
 * to manage the complete workflow of sharing files securely with other users.
 */
class FileSharingManagerUtils {
public:
    /**
     * @brief Shares a file with another user using X3DH protocol
     * 
     * This method combines all the steps required to share a file with another user:
     * 1. Generates a shared secret using X3DH protocol
     * 2. Retrieves and encrypts the file key with the shared secret
     * 3. Creates a permission on the server for the recipient
     *
     * @param fileUuid UUID of the file to share
     * @param recipientUsername Username of the recipient
     * @param recipientPublicKey Recipient's public key for X3DH protocol
     * @param parent Optional parent widget for displaying UI feedback
     * @return bool True if the file was successfully shared
     */
    static bool shareFileWithUser(
        const QString& fileUuid,
        const QString& recipientUsername,
        const QString& recipientPublicKey,
        QWidget* parent = nullptr);

private:
    /**
     * @brief Shows a progress message to the user if a parent widget is available
     * 
     * @param parent The parent widget
     * @param message The message to display
     */
    static void showProgressMessage(QWidget* parent, const QString& message);
    
    /**
     * @brief Shows an error message to the user
     * 
     * @param parent The parent widget for displaying error messages
     * @param title The error title
     * @param message The error message
     */
    static void showErrorMessage(QWidget* parent, const QString& title, const QString& message);
};

#endif // FILE_SHARING_MANAGER_UTILS_H
