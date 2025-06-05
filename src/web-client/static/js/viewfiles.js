// JavaScript for viewfiles.html
// File operation functionality for download and delete

// Initialize libsodium
let sodiumReady = false;
async function initSodium() {
    if (!sodiumReady) {
        try {
            // Wait for sodium to be available from the global script
            while (typeof sodium === 'undefined') {
                await new Promise((resolve) => setTimeout(resolve, 50));
            }
            await sodium.ready;
            sodiumReady = true;
        } catch (error) {
            console.error('Failed to initialize libsodium:', error);
            alert('Cryptographic library failed to load. Please refresh the page and try again.');
            throw error;
        }
    }
}

// Tab switching functionality
function switchTab(tab) {
    document.getElementById('owned-btn').classList.remove('active');
    document.getElementById('shared-btn').classList.remove('active');
    document.getElementById('owned-section').style.display = 'none';
    document.getElementById('shared-section').style.display = 'none';
    if (tab === 'owned') {
        document.getElementById('owned-btn').classList.add('active');
        document.getElementById('owned-section').style.display = 'block';
    } else {
        document.getElementById('shared-btn').classList.add('active');
        document.getElementById('shared-section').style.display = 'block';
    }
}

// Get user keyfile from localStorage
function getUserKeyfile() {
    try {
        const keyfileData = localStorage.getItem('fourohfour_keyfile');
        if (keyfileData) {
            return JSON.parse(keyfileData);
        }
        return null;
    } catch (error) {
        console.error('Failed to retrieve user keyfile:', error);
        return null;
    }
}

// Extract and decrypt the master key from the user's keyfile
async function getMasterKeyFromKeyfile(password) {
    try {
        await initSodium();
        const keyfile = getUserKeyfile();
        if (!keyfile || !keyfile.encrypted_master_key || !keyfile.salt) {
            console.error('Invalid keyfile: missing master key or salt');
            return null;
        }

        // Derive key from password and salt
        const salt = sodium.from_base64(keyfile.salt, sodium.base64_variants.ORIGINAL);
        const derivedKey = sodium.crypto_pwhash(
            sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
            password,
            salt,
            sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_ALG_ARGON2ID13
        );

        // Decrypt master key
        const encryptedMasterKey = sodium.from_base64(keyfile.encrypted_master_key, sodium.base64_variants.ORIGINAL);
        const nonce = encryptedMasterKey.slice(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ciphertext = encryptedMasterKey.slice(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        const masterKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, // nsec
            ciphertext,
            null, // additional data
            nonce,
            derivedKey
        );

        // Clear derived key from memory
        sodium.memzero(derivedKey);
        return masterKey;
    } catch (error) {
        console.error('Failed to extract master key:', error);
        return null;
    }
}

// Decrypt a file key using the master key
async function decryptFileKey(encryptedKeyBase64, masterKey) {
    try {
        await initSodium();
        const combined = sodium.from_base64(encryptedKeyBase64, sodium.base64_variants.ORIGINAL);
        
        const nonce = combined.slice(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ciphertext = combined.slice(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        const decryptedKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, // nsec
            ciphertext,
            null, // no additional data
            nonce,
            masterKey
        );

        return decryptedKey;
    } catch (error) {
        console.error('Failed to decrypt file key:', error);
        return null;
    }
}

// Decrypt file data with XChaCha20-Poly1305 AEAD
async function decryptFileData(encryptedData, key) {
    await initSodium();
    
    // Extract nonce and ciphertext from the encrypted data
    const nonce = encryptedData.slice(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = encryptedData.slice(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    try {
        const decryptedData = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, // nsec
            ciphertext,
            null, // no additional data
            nonce,
            key
        );
        return decryptedData;
    } catch (error) {
        console.error('Failed to decrypt file data:', error);
        throw error;
    }
}

// Prompt for password with optional error message
function promptForPassword(errorMessage = null) {
    return new Promise((resolve) => {
        // Create modal for password input
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        `;

        const modalContent = document.createElement('div');
        modalContent.style.cssText = `
            background: white;
            padding: 20px;
            border-radius: 8px;
            width: 300px;
            max-width: 90%;
        `;

        modalContent.innerHTML = `
            <h3>Password Required</h3>
            ${errorMessage ? `<p style="color: red;">${errorMessage}</p>` : ''}
            <p>Please enter your password to access the file:</p>
            <input type="password" id="password-input" placeholder="Password" style="width: 100%; padding: 8px; margin: 10px 0;">
            <div style="text-align: right; margin-top: 10px;">
                <button id="password-cancel" style="margin-right: 10px;">Cancel</button>
                <button id="password-ok">OK</button>
            </div>
        `;

        modal.appendChild(modalContent);
        document.body.appendChild(modal);

        const passwordInput = document.getElementById('password-input');
        const okButton = document.getElementById('password-ok');
        const cancelButton = document.getElementById('password-cancel');

        // Focus on password input
        setTimeout(() => passwordInput.focus(), 100);

        // Handle OK button click
        const handleOk = () => {
            const password = passwordInput.value;
            document.body.removeChild(modal);
            resolve(password);
        };

        // Handle Cancel button click
        const handleCancel = () => {
            document.body.removeChild(modal);
            resolve(null);
        };

        okButton.addEventListener('click', handleOk);
        cancelButton.addEventListener('click', handleCancel);
        
        // Handle Enter key
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleOk();
            }
        });
    });
}

// Get master key with password retry loop
async function getMasterKeyWithRetry() {
    let masterKey = null;
    let attempts = 0;
    const maxAttempts = 3;
    let errorMessage = null;

    // Try cached master key first
    const cachedMasterKey = sessionStorage.getItem('fourohfour_master_key');
    if (cachedMasterKey) {
        try {
            return sodium.from_base64(cachedMasterKey, sodium.base64_variants.ORIGINAL);
        } catch (e) {
            console.error('Failed to decode cached master key:', e);
            sessionStorage.removeItem('fourohfour_master_key');
        }
    }

    // If no cached key, prompt for password
    while (!masterKey && attempts < maxAttempts) {
        const password = await promptForPassword(errorMessage);
        if (!password) {
            return null; // User cancelled
        }

        masterKey = await getMasterKeyFromKeyfile(password);
        if (!masterKey) {
            attempts++;
            errorMessage = `Incorrect password. ${maxAttempts - attempts} attempts remaining.`;
        } else {
            // Cache the master key for future use
            sessionStorage.setItem('fourohfour_master_key', 
                sodium.to_base64(masterKey, sodium.base64_variants.ORIGINAL));
        }
    }

    if (!masterKey) {
        alert('Maximum password attempts reached. Please try again later.');
        return null;
    }

    return masterKey;
}

// Download file functionality
async function downloadFile(fileUuid, filename, isOwner) {
    let button = null;
    let originalText = '';
    
    try {
        await initSodium();

        // Find the button that triggered this call
        // Since we're called via onclick, we need to find the button manually
        const buttons = document.querySelectorAll('button');
        for (let btn of buttons) {
            if (btn.onclick && btn.onclick.toString().includes(`downloadFile('${fileUuid}'`)) {
                button = btn;
                break;
            }
        }

        if (button) {
            originalText = button.textContent;
            button.textContent = 'Downloading...';
            button.disabled = true;
        }        // Get the encrypted file from server via proxy endpoint
        const response = await fetch(`/api/files/${fileUuid}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch file: ${response.status} ${response.statusText}`);
        }

        const fileData = await response.json();
        console.log('Received file data structure:', Object.keys(fileData));

        let fileKey;
        
        if (isOwner) {
            // For owned files, decrypt using master key
            console.log('Downloading owned file...');
            
            // Get file key from keyfile
            const keyfile = getUserKeyfile();
            if (!keyfile || !keyfile.files || !keyfile.files[fileUuid]) {
                throw new Error('File key not found in keyfile');
            }

            const encryptedFileKey = keyfile.files[fileUuid];
            
            // Check if key is encrypted (has proper length) or legacy unencrypted
            if (encryptedFileKey.length > 44) { // Encrypted key is longer due to nonce + ciphertext + base64
                // Encrypted key - need master key to decrypt
                const masterKey = await getMasterKeyWithRetry();
                if (!masterKey) {
                    throw new Error('Master key required but not available');
                }
                
                fileKey = await decryptFileKey(encryptedFileKey, masterKey);
                if (!fileKey) {
                    throw new Error('Failed to decrypt file key');
                }
            } else {
                // Legacy unencrypted key
                fileKey = sodium.from_base64(encryptedFileKey, sodium.base64_variants.ORIGINAL);
            }

        } else {
            // For shared files, we need to implement X3DH decryption
            // For now, show a message that shared file download is not yet implemented
            throw new Error('Shared file download is not yet implemented in the web client. Please use the desktop client for shared files.');
            
            // TODO: Implement X3DH key agreement for shared files
            // This would require:
            // 1. Get user's private keys (identity, signed prekey, one-time prekey)
            // 2. Perform X3DH key agreement with sender's keys from fileData
            // 3. Decrypt the shared file key using the derived shared secret
            // 4. Use that key to decrypt the file
        }

        // Decrypt the file data
        const encryptedFileBuffer = sodium.from_base64(fileData.encrypted_file, sodium.base64_variants.ORIGINAL);
        const decryptedData = await decryptFileData(encryptedFileBuffer, fileKey);

        // Create and trigger download
        const blob = new Blob([decryptedData]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        console.log(`File ${filename} downloaded successfully`);    } catch (error) {
        console.error('Download failed:', error);
        alert(`Download failed: ${error.message}`);
    } finally {
        // Restore button state
        if (button) {
            button.textContent = originalText || 'Download';
            button.disabled = false;
        }
    }
}

// Delete file functionality
async function deleteFile(fileUuid, filename) {
    if (!confirm(`Are you sure you want to delete "${filename}"? This action cannot be undone.`)) {
        return;
    }

    let button = null;
    let originalText = '';

    try {
        // Find the delete button that triggered this call
        const buttons = document.querySelectorAll('button');
        for (let btn of buttons) {
            if (btn.onclick && btn.onclick.toString().includes(`deleteFile('${fileUuid}'`)) {
                button = btn;
                break;
            }
        }

        if (button) {
            originalText = button.textContent;
            button.textContent = 'Deleting...';
            button.disabled = true;
        }        // Send delete request to server via proxy endpoint
        const response = await fetch(`/api/files/${fileUuid}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            // Try to get error message from response
            let errorMessage = `Delete failed: ${response.status} ${response.statusText}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorMessage;
            } catch (jsonError) {
                // If response isn't JSON, use the status text
                console.log('Server returned non-JSON response for delete request');
            }
            throw new Error(errorMessage);
        }

        // Try to parse success response
        let successMessage = `File "${filename}" deleted successfully`;
        try {
            const responseData = await response.json();
            successMessage = responseData.message || successMessage;
        } catch (jsonError) {
            // If response isn't JSON, use default message
            console.log('Server returned non-JSON response for successful delete');
        }

        // Remove file key from local keyfile
        const keyfile = getUserKeyfile();
        if (keyfile && keyfile.files && keyfile.files[fileUuid]) {
            delete keyfile.files[fileUuid];
            keyfile.last_modified = new Date().toISOString();
            localStorage.setItem('fourohfour_keyfile', JSON.stringify(keyfile));
            console.log(`Removed file key for ${filename} from local keyfile`);
        }        // Remove the table row
        if (button) {
            const row = button.closest('tr');
            if (row) {
                row.remove();
            }
        }

        alert(successMessage);

    } catch (error) {
        console.error('Delete failed:', error);
        alert(`Delete failed: ${error.message}`);
    } finally {
        // Restore button state
        if (button) {
            button.textContent = originalText || 'Delete';
            button.disabled = false;
        }
    }
}

window.onload = function() {
    switchTab('owned');
};
