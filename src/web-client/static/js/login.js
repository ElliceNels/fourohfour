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

// Decrypt AES-GCM
async function decryptAESGCM(ciphertext, iv, key) {
    return await window.crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: iv},
        key,
        ciphertext
    );
}

// On login form submit, derive key, decrypt master key, and set session
window.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('.login-form');
    const errorDiv = document.getElementById('login-error');
    let loginInProgress = false;
    if (!form) return;
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        if (loginInProgress) return;
        loginInProgress = true;
        if (errorDiv) { errorDiv.style.display = 'none'; errorDiv.textContent = ''; }
        showLoginProgressAndDisableBtn();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        // Retrieve encrypted key data from localStorage
        const encData = localStorage.getItem('encryptedKey_' + username);
        if (!encData) {
            if (errorDiv) {
                errorDiv.textContent = 'No local key data found for this user.';
                errorDiv.style.display = 'block';
            } else {
                alert('No local key data found for this user.');
            }
            document.getElementById('login-btn').disabled = false;
            document.getElementById('login-btn').textContent = 'Log In';
            document.getElementById('password').value = '';
            loginInProgress = false;
            return;
        }
        try {
            const parsed = JSON.parse(encData);
            const salt = base64ToArrayBuffer(parsed.salt);
            const derivedKey = await deriveKeyFromPassword(password, new Uint8Array(salt));
            // Decrypt master key
            const masterIV = base64ToArrayBuffer(parsed.masterIV);
            const encryptedMasterKey = base64ToArrayBuffer(parsed.encryptedMasterKey);
            const masterKeyRaw = await decryptAESGCM(encryptedMasterKey, new Uint8Array(masterIV), derivedKey);
            sessionStorage.setItem('masterKey_' + username, arrayBufferToBase64(masterKeyRaw));
            // Now send login request to server (only for authentication, not for key material)
            const resp = await fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
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
            if (errorDiv) {
                errorDiv.textContent = 'Login error: ' + err;
                errorDiv.style.display = 'block';
            } else {
                alert('Login error: ' + err);
            }
            document.getElementById('login-btn').disabled = false;
            document.getElementById('login-btn').textContent = 'Log In';
            document.getElementById('password').value = '';
            loginInProgress = false;
        }
    });
});
