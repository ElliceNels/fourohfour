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

// Derive key from password using Argon2id (matching desktop client and signup)
async function deriveKeyFromPassword(password, salt) {
  await initSodium();
  const passwordBytes = sodium.from_string(password);

  // Use Argon2id with INTERACTIVE limits (matching desktop client)
  const derivedKey = sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES, // 32 bytes
    passwordBytes,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID
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

// Retrieve encrypted keyfile data from server
async function getEncryptedKeyfile(username) {
  try {
    const resp = await fetch('/get_encrypted_keyfile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username }),
    });

    if (!resp.ok) {
      const errorData = await resp.json();
      throw new Error(errorData.error || 'Failed to retrieve keyfile');
    }

    const data = await resp.json();
    return data.keyfile_data;
  } catch (error) {
    throw new Error(`Failed to retrieve keyfile: ${error.message}`);
  }
}

// On login form submit, derive key, decrypt master key, and set session
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

    try {
      // Initialize libsodium first
      await initSodium();

      // Retrieve encrypted key data from server instead of localStorage
      const encData = await getEncryptedKeyfile(username);

      const salt = sodium.from_base64(encData.salt);
      const derivedKey = await deriveKeyFromPassword(password, salt);

      // Decrypt master key using new format
      const encryptedMasterKeyData = sodium.from_base64(
        encData.encrypted_master_key
      );
      const masterKeyRaw = await decryptXChaCha20Poly1305(
        encryptedMasterKeyData,
        derivedKey
      );
      sessionStorage.setItem(
        'masterKey_' + username,
        sodium.to_base64(masterKeyRaw)
      );
      // Now send login request to server (only for authentication, not for key material)
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
        window.location.href = '/mainmenu';
      } else {
        const msg = result && result.error ? result.error : 'Login failed';
        if (errorDiv) {
          errorDiv.textContent = 'Login failed: ' + msg;
          errorDiv.style.display = 'block';
        } else {
          alert('Login failed: ' + msg);
        }
        document.getElementById('login-btn').disabled = false;
        document.getElementById('login-btn').textContent = 'Log In';
        document.getElementById('password').value = '';
        loginInProgress = false;
      }
    } catch (err) {
      // Handle both keyfile retrieval errors and decryption errors
      let errorMessage = 'Login error: ';
      if (err.message.includes('Failed to retrieve keyfile')) {
        errorMessage += 'No account found for this user. Please sign up first.';
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
      document.getElementById('login-btn').disabled = false;
      document.getElementById('login-btn').textContent = 'Log In';
      document.getElementById('password').value = '';
      loginInProgress = false;
    }
  });
});
