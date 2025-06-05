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

// --- TweetNaCl.js integration for Ed25519/X25519 ---
// You must include TweetNaCl.js in your HTML for this to work:
// <script src="https://cdn.jsdelivr.net/npm/tweetnacl-util@0.15.1/nacl-util.min.js"></script>
// <script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl.min.js"></script>

// Helper: base64 encode/decode using TweetNaCl
function naclEncodeBase64(bytes) {
    return nacl.util.encodeBase64(bytes);
}
function naclDecodeBase64(str) {
    return nacl.util.decodeBase64(str);
}

// Generate Ed25519 keypair using TweetNaCl
async function generateEd25519KeyPair() {
    const kp = nacl.sign.keyPair();
    return {
        publicKey: kp.publicKey,
        privateKey: kp.secretKey
    };
}

// Generate X25519 keypair (for pre-keys) using TweetNaCl
async function generateX25519KeyPair() {
    const kp = nacl.box.keyPair();
    return {
        publicKey: kp.publicKey,
        privateKey: kp.secretKey
    };
}

// Derive key from password using PBKDF2
async function deriveKeyFromPassword(password, salt, keyLen = 32) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw', enc.encode(password), {name: 'PBKDF2'}, false, ['deriveKey']
    );
    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        {name: 'AES-GCM', length: keyLen * 8},
        true,
        ['encrypt', 'decrypt']
    );
}

// Encrypt data with AES-GCM
async function encryptAESGCM(data, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await window.crypto.subtle.encrypt(
        {name: 'AES-GCM', iv: iv},
        key,
        typeof data === 'string' ? enc.encode(data) : data
    );
    return {ciphertext, iv};
}

// Store encrypted keys in localStorage (or IndexedDB for production)
function storeEncryptedKey(username, encryptedKey, encryptedMasterKey, salt) {
    localStorage.setItem('encryptedKey_' + username, JSON.stringify({
        encryptedKey: arrayBufferToBase64(encryptedKey.ciphertext),
        keyIV: arrayBufferToBase64(encryptedKey.iv),
        encryptedMasterKey: arrayBufferToBase64(encryptedMasterKey.ciphertext),
        masterIV: arrayBufferToBase64(encryptedMasterKey.iv),
        salt: arrayBufferToBase64(salt)
    }));
}

// Generate a signed pre-key (X25519 + Ed25519 signature)
async function generateSignedPreKey(identityKeyPair) {
    const spk = await generateX25519KeyPair();
    // Sign the public key with Ed25519 identity private key
    const signature = nacl.sign.detached(spk.publicKey, identityKeyPair.privateKey);
    return {
        spkPub: naclEncodeBase64(spk.publicKey),
        spkPriv: spk.privateKey, // not sent to server
        signature: naclEncodeBase64(signature)
    };
}

// Generate one-time pre-keys (X25519)
async function generateOneTimePreKeys(count = 10) {
    let publicKeys = [];
    let privateKeys = [];
    for (let i = 0; i < count; i++) {
        const kp = await generateX25519KeyPair();
        publicKeys.push(naclEncodeBase64(kp.publicKey));
        privateKeys.push(kp.privateKey); // not sent to server
    }
    // Store privateKeys in browser storage if needed
    return publicKeys;
}

// Intercept signup form submission
window.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('.signup-form');
    if (!form) return;
    form.addEventListener('submit', async function(e) {
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
            // 1. Generate identity keypair (Ed25519)
            const idKeyPair = await generateEd25519KeyPair();
            const pubKeyB64 = naclEncodeBase64(idKeyPair.publicKey);
            // 2. Generate salt and derive key
            const salt = generateSalt();
            const derivedKey = await deriveKeyFromPassword(password, salt);
            // 3. Encrypt and store private key
            const privKeyRaw = idKeyPair.privateKey;
            const encryptedKey = await encryptAESGCM(privKeyRaw, derivedKey);
            // 4. Generate random master key and encrypt it with derived key
            const masterKey = window.crypto.getRandomValues(new Uint8Array(32));
            const encryptedMasterKey = await encryptAESGCM(masterKey, derivedKey);
            // 5. Store encrypted keys in browser
            storeEncryptedKey(username, encryptedKey, encryptedMasterKey, salt);
            // 6. Generate signed pre-key
            const spk = await generateSignedPreKey(idKeyPair);
            // 7. Generate one-time pre-keys
            const otpk = await generateOneTimePreKeys(10);
            // 8. Send public data to server (include password for backend authentication)
            const payload = {
                username: username,
                password: password, // send password for backend authentication
                public_key: pubKeyB64,
                salt: naclEncodeBase64(salt),
                spk: spk.spkPub,
                spk_signature: spk.signature,
                otpks: otpk
            };
            const resp = await fetch('/signup', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
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
                    msg = 'Registration failed. Please check your details or try again later.';
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

// Generate random salt
function generateSalt(length = 16) {
    let salt = new Uint8Array(length);
    window.crypto.getRandomValues(salt);
    return salt;
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
