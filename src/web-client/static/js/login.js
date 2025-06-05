// JavaScript for login.html
function togglePassword() {
  const pwd = document.getElementById('password');
  const btn = document.getElementById('show-btn');
  if (pwd.type === 'password') {
    pwd.type = 'text';
    btn.textContent = 'Hide';
  } else {
    pwd.type = 'password';
    btn.textContent = 'Show';
  }
}

function showLoginProgressAndDisableBtn() {
  var btn = document.getElementById('login-btn');
  btn.disabled = true;
  btn.textContent = 'Logging in...';
}

// --- Libsodium.js integration for Argon2id/XChaCha20-Poly1305 ---
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
      console.log('Libsodium initialized successfully');
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

// Helper: Convert base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  let binary = window.atob(base64);
  let bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Derive key from password using Argon2 (matching desktop client and signup)
async function deriveKeyFromPassword(password, salt) {
  await initSodium();
  const passwordBytes = sodium.from_string(password);

  // Try to use the best available algorithm (same logic as signup)
  let algorithm;
  if (typeof sodium.crypto_pwhash_ALG_ARGON2ID !== 'undefined') {
    algorithm = sodium.crypto_pwhash_ALG_ARGON2ID;
    console.log('Using Argon2ID algorithm');
  } else if (typeof sodium.crypto_pwhash_ALG_ARGON2I !== 'undefined') {
    algorithm = sodium.crypto_pwhash_ALG_ARGON2I;
    console.log('Using Argon2I algorithm');
  } else if (typeof sodium.crypto_pwhash_ALG_DEFAULT !== 'undefined') {
    algorithm = sodium.crypto_pwhash_ALG_DEFAULT;
    console.log('Using default algorithm');
  } else {
    throw new Error('No password hashing algorithm available');
  }

  // Use Argon2 with INTERACTIVE limits (matching desktop client)
  const derivedKey = sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES, // 32 bytes
    passwordBytes,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    algorithm
  );

  return derivedKey;
}

// Decrypt XChaCha20-Poly1305 AEAD (matching desktop client format)
async function decryptXChaCha20Poly1305(combinedData, key) {
  await initSodium();

  // Extract nonce and ciphertext following desktop client format: [nonce][ciphertext]
  const nonceSize = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  const nonce = combinedData.slice(0, nonceSize);
  const ciphertext = combinedData.slice(nonceSize);

  const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, // nsec not used
    ciphertext,
    null, // no additional data
    nonce,
    key
  );

  return decrypted;
}

// Retrieve keyfile from localStorage or uploaded file
function getStoredKeyfile() {
  try {
    const stored = localStorage.getItem('fourohfour_keyfile');
    if (stored) {
      return JSON.parse(stored);
    }
    return null;
  } catch (error) {
    console.error('Failed to retrieve keyfile from localStorage:', error);
    return null;
  }
}

// Store uploaded keyfile in localStorage
function storeUploadedKeyfile(keyfileData) {
  try {
    localStorage.setItem('fourohfour_keyfile', JSON.stringify(keyfileData));
    console.log('Uploaded keyfile stored in localStorage');
    return true;
  } catch (error) {
    console.error('Failed to store uploaded keyfile:', error);
    return false;
  }
}

// Clear keyfile from localStorage (on logout)
function clearStoredKeyfile() {
  try {
    localStorage.removeItem('fourohfour_keyfile');
    console.log('Keyfile cleared from localStorage');
  } catch (error) {
    console.error('Failed to clear keyfile from localStorage:', error);
  }
}

// Process uploaded keyfile
async function processUploadedKeyfile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const keyfileData = JSON.parse(e.target.result);

        // Validate keyfile structure
        if (
          !keyfileData.encrypted_key ||
          !keyfileData.encrypted_master_key ||
          !keyfileData.salt
        ) {
          reject(new Error('Invalid keyfile format: missing required fields'));
          return;
        }

        // Store in localStorage for future use
        storeUploadedKeyfile(keyfileData);
        resolve(keyfileData);
      } catch (error) {
        reject(new Error('Invalid keyfile format: ' + error.message));
      }
    };
    reader.onerror = function () {
      reject(new Error('Failed to read keyfile'));
    };
    reader.readAsText(file);
  });
}

// On login form submit, process keyfile and authenticate
window.addEventListener('DOMContentLoaded', function () {
  const form = document.querySelector('.login-form');
  const errorDiv = document.getElementById('login-error');
  let loginInProgress = false;

  if (!form) return;

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (loginInProgress) return;
    loginInProgress = true;

    if (errorDiv) {
      errorDiv.style.display = 'none';
      errorDiv.textContent = '';
    }
    showLoginProgressAndDisableBtn();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const keyfileInput = document.getElementById('keyfile');

    try {
      // Initialize libsodium first
      await initSodium();

      let keyfileData;

      // Check if user uploaded a keyfile
      if (keyfileInput && keyfileInput.files.length > 0) {
        console.log('Processing uploaded keyfile...');
        keyfileData = await processUploadedKeyfile(keyfileInput.files[0]);
      } else {
        // Try to get keyfile from localStorage
        console.log('Checking localStorage for keyfile...');
        keyfileData = getStoredKeyfile();
        if (!keyfileData) {
          throw new Error(
            'No keyfile found. Please upload your keyfile or ensure it was saved during signup.'
          );
        }
      }

      // Validate username matches keyfile
      if (keyfileData.username && keyfileData.username !== username) {
        throw new Error(
          'Username does not match the keyfile. Please check your credentials.'
        );
      }

      const salt = sodium.from_base64(
        keyfileData.salt,
        sodium.base64_variants.ORIGINAL
      );
      const derivedKey = await deriveKeyFromPassword(password, salt);

      // Decrypt master key using keyfile data
      const encryptedMasterKeyData = sodium.from_base64(
        keyfileData.encrypted_master_key,
        sodium.base64_variants.ORIGINAL
      );
      const masterKeyRaw = await decryptXChaCha20Poly1305(
        encryptedMasterKeyData,
        derivedKey
      );

      // Store master key in session
      sessionStorage.setItem(
        'masterKey_' + username,
        sodium.to_base64(masterKeyRaw, sodium.base64_variants.ORIGINAL)
      );

      // Now authenticate with backend server (password still needed for server auth)
      const resp = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      let result;
      try {
        result = await resp.json();
      } catch (e) {
        result = { success: false, error: 'Invalid server response' };
      }

      if (resp.ok && result.success) {
        console.log('Login successful, keyfile available for session');
        window.location.href = '/mainmenu';
      } else {
        const msg = result && result.error ? result.error : 'Login failed';
        if (errorDiv) {
          errorDiv.textContent = 'Login failed: ' + msg;
          errorDiv.style.display = 'block';
        } else {
          alert('Login failed: ' + msg);
        }
        resetLoginForm();
      }
    } catch (err) {
      // Handle keyfile and authentication errors
      let errorMessage = 'Login error: ';
      if (err.message.includes('keyfile')) {
        errorMessage += err.message;
      } else if (err.message.includes('decrypt')) {
        errorMessage += 'Invalid password or corrupted keyfile.';
      } else {
        errorMessage += err.message;
      }

      if (errorDiv) {
        errorDiv.textContent = errorMessage;
        errorDiv.style.display = 'block';
      } else {
        alert(errorMessage);
      }
      resetLoginForm();
    }
  });

  function resetLoginForm() {
    document.getElementById('login-btn').disabled = false;
    document.getElementById('login-btn').textContent = 'Log In';
    document.getElementById('password').value = '';
    loginInProgress = false;
  }
});
