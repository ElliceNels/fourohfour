/**
 * Secure File Upload with Encrypted Key Storage
 * ============================================
 *
 * This module implements client-side file encryption with secure key management,
 * matching the desktop client's security model:
 *
 * 1. FILE ENCRYPTION: Files are encrypted with XChaCha20-Poly1305 using random symmetric keys
 * 2. KEY ENCRYPTION: File keys are encrypted using the user's master key before storage
 * 3. MASTER KEY: Derived from user password, used to encrypt/decrypt file keys
 * 4. STORAGE FORMAT: Encrypted keys stored in user's main keyfile (JSON structure)
 *
 * Security Features:
 * - File keys are encrypted with master key (matching desktop client)
 * - Master key cached in session storage for convenience
 * - Automatic password prompts when master key needed
 * - Backward compatibility with legacy unencrypted key storage
 * - Graceful fallback to unencrypted storage if master key unavailable
 *
 * Integration:
 * - Call initializeMasterKeyFromLogin(password) after successful login
 * - Call clearCachedMasterKey() on logout
 * - File upload automatically handles key encryption and storage
 */

// Secure file upload: browser-side encryption using libsodium-js
// Must include libsodium-js in HTML:
// <script src="https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.13/dist/sodium.js"></script>

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
      alert(
        'Cryptographic library failed to load. Please refresh the page and try again.'
      );
      throw error;
    }
  }
}

// Helper: Convert ArrayBuffer to base64
function arrayBufferToBase64(buffer) {
  let binary = '';
  let bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper: Generate a random XChaCha20-Poly1305 key using libsodium
async function generateSymmetricKey() {
  await initSodium();
  return sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
  );
}

// Helper: Encrypt file data with XChaCha20-Poly1305 AEAD
async function encryptFileData(fileBuffer, key) {
  await initSodium();
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const fileData = new Uint8Array(fileBuffer);

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    fileData,
    null, // no additional data
    null, // nsec not used
    nonce,
    key
  );

  return { ciphertext, nonce };
}

// Store the symmetric key in localStorage (per file UUID)
function storeFileKey(fileUuid, key) {
  localStorage.setItem(
    'filekey_' + fileUuid,
    sodium.to_base64(key, sodium.base64_variants.ORIGINAL)
  );
}

// Get current user's keyfile from localStorage
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
    const salt = sodium.from_base64(
      keyfile.salt,
      sodium.base64_variants.ORIGINAL
    );
    const derivedKey = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      password,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13 // Corrected constant
    );

    // Decrypt master key
    const encryptedMasterKey = sodium.from_base64(
      keyfile.encrypted_master_key,
      sodium.base64_variants.ORIGINAL
    );
    const nonce = encryptedMasterKey.slice(
      0,
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );
    const ciphertext = encryptedMasterKey.slice(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );

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

// Encrypt a file key using the master key
async function encryptFileKey(fileKey, masterKey) {
  try {
    await initSodium();
    const nonce = sodium.randombytes_buf(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );

    const encryptedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      fileKey,
      null, // no additional data
      null, // nsec not used
      nonce,
      masterKey
    );

    // Combine nonce and ciphertext: [nonce][ciphertext]
    const combined = new Uint8Array(nonce.length + encryptedKey.length);
    combined.set(nonce, 0);
    combined.set(encryptedKey, nonce.length);

    return sodium.to_base64(combined, sodium.base64_variants.ORIGINAL);
  } catch (error) {
    console.error('Failed to encrypt file key:', error);
    return null;
  }
}

// Decrypt a file key using the master key
async function decryptFileKey(encryptedKeyBase64, masterKey) {
  try {
    await initSodium();
    const combined = sodium.from_base64(
      encryptedKeyBase64,
      sodium.base64_variants.ORIGINAL
    );

    const nonce = combined.slice(
      0,
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );
    const ciphertext = combined.slice(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );

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

// Update user keyfile with new file key (with encryption)
async function addFileKeyToUserKeyfile(
  fileUuid,
  key,
  filename,
  password = null
) {
  try {
    // Get current user keyfile
    let keyfile = getUserKeyfile();
    if (!keyfile) {
      console.error('No user keyfile found. Cannot add file key.');
      return false;
    }

    // Get master key for encryption (try to get from session first, then prompt if needed)
    let masterKey = null;
    if (password) {
      masterKey = await getMasterKeyFromKeyfile(password);
    } else {
      // Try to get cached master key if available
      const cachedMasterKey = sessionStorage.getItem('fourohfour_master_key');
      if (cachedMasterKey) {
        masterKey = sodium.from_base64(
          cachedMasterKey,
          sodium.base64_variants.ORIGINAL
        );
      } else {
        console.warn(
          'No master key available for file key encryption. Storing unencrypted (less secure).'
        );
      }
    }

    // Initialize files section if it doesn't exist
    if (!keyfile.files) {
      keyfile.files = {};
    }

    let keyToStore;
    if (masterKey) {
      // Encrypt the file key using the master key (secure method)
      keyToStore = await encryptFileKey(key, masterKey);
      if (!keyToStore) {
        console.error(
          'Failed to encrypt file key. Falling back to unencrypted storage.'
        );
        keyToStore = sodium.to_base64(key, sodium.base64_variants.ORIGINAL);
      } else {
        console.log('File key encrypted successfully before storage');
      }
    } else {
      // Store unencrypted as fallback (less secure but functional)
      keyToStore = sodium.to_base64(key, sodium.base64_variants.ORIGINAL);
      console.warn('Storing file key unencrypted (master key not available)');
    }

    // Add the file key to the keyfile (matching desktop client JSON structure)
    keyfile.files[fileUuid] = keyToStore; // Simple UUID -> encrypted_key mapping like desktop client

    // Update the keyfile version and modification time
    keyfile.version = keyfile.version || '1.0';
    keyfile.last_modified = new Date().toISOString();

    // Store the updated keyfile in localStorage
    localStorage.setItem('fourohfour_keyfile', JSON.stringify(keyfile));

    console.log(
      `Added encrypted file key for ${filename} (${fileUuid}) to user keyfile`
    );
    return true;
  } catch (error) {
    console.error('Failed to add file key to user keyfile:', error);
    return false;
  }
}

// Update localStorage with current keyfile state (useful after downloads)
function updateStoredKeyfile(keyfile) {
  try {
    localStorage.setItem('fourohfour_keyfile', JSON.stringify(keyfile));
    console.log('Keyfile updated in localStorage');
    return true;
  } catch (error) {
    console.error('Failed to update keyfile in localStorage:', error);
    return false;
  }
}

// Download updated user keyfile (with file picker support if available)
async function downloadUpdatedUserKeyfile() {
  try {
    const keyfile = getUserKeyfile();
    if (!keyfile) {
      console.error('No user keyfile found for download');
      return false;
    }

    const jsonString = JSON.stringify(keyfile, null, 2);
    const filename = `${keyfile.username}_keyfile.json`;

    // Try to use File System Access API for better user experience (Chrome 86+)
    if ('showSaveFilePicker' in window) {
      try {
        const fileHandle = await window.showSaveFilePicker({
          suggestedName: filename,
          types: [
            {
              description: 'Keyfile',
              accept: { 'application/json': ['.json'] },
            },
          ],
        });

        const writable = await fileHandle.createWritable();
        await writable.write(jsonString);
        await writable.close();

        console.log(`Updated keyfile saved via file picker: ${filename}`);
        return true;
      } catch (filePickerError) {
        // User cancelled or API failed, fall back to download
        console.log(
          'File picker cancelled or failed, falling back to download'
        );
      }
    }

    // Fallback to traditional download method
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
    console.log(`Updated keyfile downloaded: ${filename}`);
    return true;
  } catch (error) {
    console.error('Failed to download updated keyfile:', error);
    return false;
  }
}

// Legacy function for compatibility - creates separate .key files (deprecated)
// Note: These individual keyfiles are NOT encrypted for backward compatibility
function saveKeyfileToDisk(fileUuid, key, filename) {
  const keyBase64 = sodium.to_base64(key, sodium.base64_variants.ORIGINAL);
  const keyfileContent = JSON.stringify({
    uuid: fileUuid,
    filename: filename,
    key: keyBase64, // Stored unencrypted in individual .key files for compatibility
    created: new Date().toISOString(),
    version: '1.0',
  });

  // Create downloadable keyfile
  const blob = new Blob([keyfileContent], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filename}.key`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Load keyfile from disk
function loadKeyfileFromDisk(callback) {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.key';
  input.onchange = function (event) {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = function (e) {
        try {
          const keyfileData = JSON.parse(e.target.result);
          if (keyfileData.uuid && keyfileData.key) {
            // Store key in localStorage
            localStorage.setItem(
              'filekey_' + keyfileData.uuid,
              keyfileData.key
            );
            callback(null, keyfileData);
          } else {
            callback(new Error('Invalid keyfile format'));
          }
        } catch (error) {
          callback(error);
        }
      };
      reader.readAsText(file);
    }
  };
  input.click();
}

// Cache the master key in session storage (call this after successful login)
function cacheMasterKey(masterKey) {
  try {
    sessionStorage.setItem(
      'fourohfour_master_key',
      sodium.to_base64(masterKey, sodium.base64_variants.ORIGINAL)
    );
    console.log('Master key cached in session storage');
  } catch (error) {
    console.error('Failed to cache master key:', error);
  }
}

// Clear cached master key (call this on logout)
function clearCachedMasterKey() {
  sessionStorage.removeItem('fourohfour_master_key');
  console.log('Master key cleared from session storage');
}

// Initialize master key from login (call this after successful login with password)
async function initializeMasterKeyFromLogin(password) {
  try {
    const masterKey = await getMasterKeyFromKeyfile(password);
    if (masterKey) {
      cacheMasterKey(masterKey);
      console.log('Master key initialized and cached from login');
      return true;
    } else {
      console.error('Failed to initialize master key from login');
      return false;
    }
  } catch (error) {
    console.error('Error initializing master key from login:', error);
    return false;
  }
}

// Prompt user for password to decrypt master key
async function promptForPassword(
  message = 'Please enter your password to decrypt file keys:'
) {
  return new Promise((resolve) => {
    // Create a simple modal for password input
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center;
      z-index: 10000;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      background: white; padding: 20px; border-radius: 8px; min-width: 300px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    `;

    content.innerHTML = `
      <h3 style="margin-top: 0;">${message}</h3>
      <input type="password" id="password-input" style="width: 100%; padding: 8px; margin: 10px 0;" placeholder="Password">
      <div style="text-align: right; margin-top: 15px;">
        <button id="cancel-btn" style="margin-right: 10px; padding: 8px 16px;">Cancel</button>
        <button id="ok-btn" style="padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px;">OK</button>
      </div>
    `;

    modal.appendChild(content);
    document.body.appendChild(modal);

    const passwordInput = content.querySelector('#password-input');
    const okBtn = content.querySelector('#ok-btn');
    const cancelBtn = content.querySelector('#cancel-btn');

    passwordInput.focus();

    const cleanup = () => {
      document.body.removeChild(modal);
    };

    const handleOk = () => {
      const password = passwordInput.value;
      cleanup();
      resolve(password || null);
    };

    const handleCancel = () => {
      cleanup();
      resolve(null);
    };

    okBtn.addEventListener('click', handleOk);
    cancelBtn.addEventListener('click', handleCancel);
    passwordInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        handleOk();
      } else if (e.key === 'Escape') {
        handleCancel();
      }
    });
  });
}

// Get stored key for a file UUID (with decryption support)
async function getStoredKey(fileUuid, password = null) {
  try {
    // First try legacy localStorage key storage
    const legacyKeyBase64 = localStorage.getItem('filekey_' + fileUuid);
    if (legacyKeyBase64) {
      console.log('Found legacy unencrypted key for file:', fileUuid);
      return sodium.from_base64(
        legacyKeyBase64,
        sodium.base64_variants.ORIGINAL
      );
    }

    // Try to get from user's main keyfile
    const keyfile = getUserKeyfile();
    if (!keyfile || !keyfile.files || !keyfile.files[fileUuid]) {
      console.error('No key found for file UUID:', fileUuid);
      return null;
    }

    const storedKey = keyfile.files[fileUuid];

    // Try to get master key for decryption
    let masterKey = null;
    if (password) {
      masterKey = await getMasterKeyFromKeyfile(password);
    } else {
      // Try to get cached master key
      const cachedMasterKey = sessionStorage.getItem('fourohfour_master_key');
      if (cachedMasterKey) {
        masterKey = sodium.from_base64(
          cachedMasterKey,
          sodium.base64_variants.ORIGINAL
        );
      }
    }

    if (masterKey) {
      // Try to decrypt the key (it might be encrypted)
      const decryptedKey = await decryptFileKey(storedKey, masterKey);
      if (decryptedKey) {
        console.log('Successfully decrypted file key for:', fileUuid);
        return decryptedKey;
      } else {
        console.warn('Failed to decrypt key, trying as unencrypted fallback');
      }
    }

    // Fallback: treat as unencrypted base64 key
    try {
      const unencryptedKey = sodium.from_base64(
        storedKey,
        sodium.base64_variants.ORIGINAL
      );
      console.warn('Using unencrypted key for file:', fileUuid);
      return unencryptedKey;
    } catch (error) {
      console.error('Failed to decode key as base64:', error);
      return null;
    }
  } catch (error) {
    console.error('Failed to retrieve stored key:', error);
    return null;
  }
}

window.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('upload-form');
  if (!form) return;

  // Add the triggerBrowse function to trigger file input click
  window.triggerBrowse = function () {
    document.getElementById('file-input').click();
  };

  // Add the updateFileInfo function to update file details
  window.updateFileInfo = function (input) {
    const file = input.files[0];
    if (file) {
      // Show file details
      document.getElementById('file-name').value = file.name;
      document.getElementById('file-type').value = file.type || 'Unknown';
      document.getElementById('file-size').value = formatFileSize(file.size);

      // Show the file details box and confirm button
      document.getElementById('upload-details').style.display = 'block';
      document.getElementById('upload-instructions').style.display = 'block';
      document.getElementById('confirm-btn').style.display = 'inline-block';
    }
  };

  // Helper function to format file size
  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    else if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
    else return (bytes / 1073741824).toFixed(2) + ' GB';
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();

    const fileInput = document.getElementById('file-input');
    if (!fileInput.files.length) {
      alert('Please select a file.');
      return;
    }
    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer(); // 1. Initialize libsodium and generate symmetric key
    await initSodium();
    const key = await generateSymmetricKey();
    const { ciphertext, nonce } = await encryptFileData(arrayBuffer, key);

    // 2. Prepare payload following desktop client format: [nonce][ciphertext]
    const combinedData = new Uint8Array(nonce.length + ciphertext.length);
    combinedData.set(nonce, 0);
    combinedData.set(ciphertext, nonce.length);
    const payload = {
      file: {
        filename: file.name,
        contents: arrayBufferToBase64(combinedData),
      },
      metadata: {
        size: combinedData.length, // Use encrypted file size (original + encryption overhead)
        format: file.type || '-',
      },
    }; // 3. Upload to server (using Flask session authentication)
    const resp = await fetch('/api/files/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (resp.ok) {
      const result = await resp.json();
      const fileUuid = result.uuid;
      // 4. Store the symmetric key locally, indexed by file UUID
      storeFileKey(fileUuid, key);
      // 5. Add file key to user's main keyfile with encryption
      let keyfileUpdated = false;

      // Try to get master key from cache first
      let masterKey = null;
      const cachedMasterKey = sessionStorage.getItem('fourohfour_master_key');
      if (cachedMasterKey) {
        try {
          masterKey = sodium.from_base64(
            cachedMasterKey,
            sodium.base64_variants.ORIGINAL
          );
          keyfileUpdated = await addFileKeyToUserKeyfile(
            fileUuid,
            key,
            file.name
          );
        } catch (error) {
          console.error('Failed to use cached master key:', error);
        }
      }

      // If no cached master key or failed, prompt for password
      if (!keyfileUpdated) {
        const password = await promptForPassword(
          'Enter your password to encrypt and save the file key:'
        );
        if (password) {
          // Get master key and cache it for future use
          masterKey = await getMasterKeyFromKeyfile(password);
          if (masterKey) {
            cacheMasterKey(masterKey);
            keyfileUpdated = await addFileKeyToUserKeyfile(
              fileUuid,
              key,
              file.name,
              password
            );
          } else {
            console.error(
              'Failed to decrypt master key with provided password'
            );
          }
        } else {
          console.log(
            'User cancelled password entry, falling back to unencrypted storage'
          );
          keyfileUpdated = await addFileKeyToUserKeyfile(
            fileUuid,
            key,
            file.name
          );
        }
      }

      if (keyfileUpdated) {
        // Download the updated keyfile with the new file key included
        const downloadSuccess = await downloadUpdatedUserKeyfile();

        if (downloadSuccess) {
          alert(
            'File uploaded successfully! Your updated keyfile has been saved. You can replace your existing keyfile with this updated version.'
          );
        } else {
          // Fallback to legacy method if download fails
          saveKeyfileToDisk(fileUuid, key, file.name);
          alert(
            'File uploaded successfully! A separate keyfile has been saved to your downloads folder as fallback.'
          );
        }
      } else {
        // Fallback to legacy method if keyfile update fails
        saveKeyfileToDisk(fileUuid, key, file.name);
        alert(
          'File uploaded successfully! A separate keyfile has been saved to your downloads folder (keyfile integration failed).'
        );
      }

      window.location.href = '/view_files';
    } else {
      const msg = await resp.text();
      alert('Upload failed: ' + msg);
    }
  });
});
