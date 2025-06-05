// JavaScript for signup.html
function togglePassword() {
  const pwd = document.getElementById('password');
  const confirm = document.getElementById('confirm_password');
  const btn = document.getElementById('show-btn');
  if (pwd.type === 'password') {
    pwd.type = 'text';
    confirm.type = 'text';
    btn.textContent = 'Hide';
  } else {
    pwd.type = 'password';
    confirm.type = 'password';
    btn.textContent = 'Show';
  }
}

function showProgressAndDisableBtn() {
  document.getElementById('signup-btn').disabled = true;
  document.getElementById('signup-btn').textContent = 'Registering...';
}

// --- Libsodium.js integration for Ed25519/XChaCha20-Poly1305 ---
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

      // Debug: Log all available crypto_pwhash constants
      console.log(
        'Available sodium properties:',
        Object.keys(sodium).filter((k) => k.includes('crypto_pwhash'))
      );
      console.log(
        'crypto_pwhash_ALG_ARGON2I:',
        sodium.crypto_pwhash_ALG_ARGON2I
      );
      console.log(
        'crypto_pwhash_ALG_ARGON2ID:',
        sodium.crypto_pwhash_ALG_ARGON2ID
      );
      console.log(
        'crypto_pwhash_ALG_DEFAULT:',
        sodium.crypto_pwhash_ALG_DEFAULT
      );

      // Check if we have any Argon2 algorithm available
      if (
        typeof sodium.crypto_pwhash_ALG_ARGON2I === 'undefined' &&
        typeof sodium.crypto_pwhash_ALG_ARGON2ID === 'undefined' &&
        typeof sodium.crypto_pwhash_ALG_DEFAULT === 'undefined'
      ) {
        throw new Error(
          'No Argon2 algorithms available - make sure libsodium sumo version is properly loaded'
        );
      }
    } catch (error) {
      console.error('Failed to initialize libsodium:', error);
      alert(
        'Cryptographic library failed to load. Please refresh the page and try again.'
      );
      throw error;
    }
  }
}

// Generate Ed25519 keypair using libsodium
async function generateEd25519KeyPair() {
  await initSodium();
  const keypair = sodium.crypto_sign_keypair();
  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
  };
}

// Generate X25519 keypair (for pre-keys) using libsodium
async function generateX25519KeyPair() {
  await initSodium();
  const keypair = sodium.crypto_box_keypair();
  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
  };
}

// Derive key from password using Argon2 (try different algorithms in order of preference)
async function deriveKeyFromPassword(password, salt) {
  await initSodium();
  const passwordBytes = sodium.from_string(password);

  // Debug: Check if constants are available
  console.log('crypto_pwhash_ALG_ARGON2I:', sodium.crypto_pwhash_ALG_ARGON2I);
  console.log('crypto_pwhash_ALG_ARGON2ID:', sodium.crypto_pwhash_ALG_ARGON2ID);
  console.log('crypto_pwhash_ALG_DEFAULT:', sodium.crypto_pwhash_ALG_DEFAULT);
  console.log(
    'crypto_pwhash_OPSLIMIT_INTERACTIVE:',
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
  );
  console.log(
    'crypto_pwhash_MEMLIMIT_INTERACTIVE:',
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  );

  // Try to use the best available algorithm
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

  // Use Argon2 with INTERACTIVE limits
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

// Encrypt data with XChaCha20-Poly1305 AEAD (matching desktop client)
async function encryptXChaCha20Poly1305(data, key) {
  await initSodium();
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const dataBytes = typeof data === 'string' ? sodium.from_string(data) : data;

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    dataBytes,
    null, // no additional data
    null, // nsec not used
    nonce,
    key
  );

  return { ciphertext, nonce };
}

// Store encrypted keys following desktop client pattern: [nonce][ciphertext]
// No longer using localStorage - will send to server for storage
function prepareEncryptedKeyData(encryptedKey, encryptedMasterKey, salt) {
  return {
    encrypted_key: sodium.to_base64(
      combineNonceCiphertext(encryptedKey.nonce, encryptedKey.ciphertext)
    ),
    encrypted_master_key: sodium.to_base64(
      combineNonceCiphertext(
        encryptedMasterKey.nonce,
        encryptedMasterKey.ciphertext
      )
    ),
    salt: sodium.to_base64(salt),
  };
}

// Combine nonce and ciphertext following desktop client format
function combineNonceCiphertext(nonce, ciphertext) {
  const combined = new Uint8Array(nonce.length + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, nonce.length);
  return combined;
}

// Generate a signed pre-key (X25519 + Ed25519 signature)
async function generateSignedPreKey(identityKeyPair) {
  await initSodium();
  const spk = await generateX25519KeyPair();
  // Sign the public key with Ed25519 identity private key
  const signature = sodium.crypto_sign_detached(
    spk.publicKey,
    identityKeyPair.privateKey
  );
  return {
    spkPub: sodium.to_base64(spk.publicKey),
    spkPriv: spk.privateKey, // not sent to server
    signature: sodium.to_base64(signature),
  };
}

// Generate one-time pre-keys (X25519)
async function generateOneTimePreKeys(count = 10) {
  await initSodium();
  let publicKeys = [];
  let privateKeys = [];
  for (let i = 0; i < count; i++) {
    const kp = await generateX25519KeyPair();
    publicKeys.push(sodium.to_base64(kp.publicKey));
    privateKeys.push(kp.privateKey); // not sent to server
  }
  // Store privateKeys in browser storage if needed
  return publicKeys;
}

// Intercept signup form submission
window.addEventListener('DOMContentLoaded', async function () {
  console.log('DOM loaded, initializing libsodium...');

  const form = document.querySelector('.signup-form');
  if (!form) return;

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    showProgressAndDisableBtn();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    console.log('Username:', password);
    const confirm = document.getElementById('confirm_password').value;
    if (password !== confirm) {
      alert('Passwords do not match!');
      return;
    }
    try {
      // Initialize libsodium first
      await initSodium();

      // 1. Generate identity keypair (Ed25519)
      const idKeyPair = await generateEd25519KeyPair();
      const pubKeyB64 = sodium.to_base64(idKeyPair.publicKey);

      // 2. Generate salt and derive key using Argon2id
      const salt = sodium.randombytes_buf(16); // 16 bytes salt
      const derivedKey = await deriveKeyFromPassword(password, salt);

      // 3. Encrypt private key with XChaCha20-Poly1305
      const encryptedKey = await encryptXChaCha20Poly1305(
        idKeyPair.privateKey,
        derivedKey
      );
      // 4. Generate random master key and encrypt it with derived key
      const masterKey = sodium.randombytes_buf(
        sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
      );
      const encryptedMasterKey = await encryptXChaCha20Poly1305(
        masterKey,
        derivedKey
      );

      // 5. Prepare encrypted keyfile data for server storage
      const keyfileData = prepareEncryptedKeyData(
        encryptedKey,
        encryptedMasterKey,
        salt
      );

      // 6. Generate signed pre-key
      const spk = await generateSignedPreKey(idKeyPair);
      // 7. Generate one-time pre-keys
      const otpk = await generateOneTimePreKeys(10);

      // 8. Send public data AND encrypted keyfile data to server
      const payload = {
        username: username,
        password: password, // send password for backend authentication
        public_key: pubKeyB64,
        salt: sodium.to_base64(salt),
        spk: spk.spkPub,
        spk_signature: spk.signature,
        otpks: otpk,
        // Add encrypted keyfile data for server-side storage
        encrypted_key: keyfileData.encrypted_key,
        encrypted_master_key: keyfileData.encrypted_master_key,
      };
      const resp = await fetch('/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (resp.ok) {
        window.location.href = '/mainmenu';
      } else {
        let msg;
        try {
          // Try to parse as JSON error
          const data = await resp.json();
          msg = data.error || data.message || 'Registration failed';
        } catch (e) {
          // Fallback: show generic error if not JSON
          msg =
            'Registration failed. Please check your details or try again later.';
        }
        alert('Registration failed: ' + msg);
        document.getElementById('signup-btn').disabled = false;
        document.getElementById('signup-btn').textContent = 'Create Account';
      }
    } catch (err) {
      alert('Registration error: ' + err);
      document.getElementById('signup-btn').disabled = false;
      document.getElementById('signup-btn').textContent = 'Create Account';
    }
  });
});

// Generate random salt (16 bytes to match desktop client)
function generateSalt(length = 16) {
  return sodium.randombytes_buf(length);
}

// Helper: Convert ArrayBuffer/Uint8Array to base64 (for compatibility)
function arrayBufferToBase64(buffer) {
  if (buffer instanceof Uint8Array) buffer = buffer.buffer;
  let binary = '';
  let bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}
