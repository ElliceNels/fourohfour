function updateFileInfo(input) {
  if (input.files.length > 0) {
    const file = input.files[0];
    const maxSize = 10 * 1024 * 1024; // 10 MB in bytes

    if (file.size > maxSize) {
      alert('File is too large! Maximum allowed size is 10MB.');
      input.value = ''; // Clear the file input
      // Optionally, hide details and confirm button if previously shown
      document.getElementById('upload-details').style.display = 'none';
      document.getElementById('upload-instructions').style.display = 'none';
      document.getElementById('confirm-btn').style.display = 'none';
      return;
    }

    const fileName = document.getElementById('file-name');
    const fileType = document.getElementById('file-type');
    const fileSize = document.getElementById('file-size');
    const uploadDetails = document.getElementById('upload-details');
    const uploadInstructions = document.getElementById('upload-instructions');
    const confirmBtn = document.getElementById('confirm-btn');

    fileName.value = file.name;
    // Use MIME type instead of file extension
    fileType.value = file.type || '-';
    fileSize.value = `${file.size} bytes`;

    uploadDetails.style.display = 'block';
    uploadInstructions.style.display = 'block';
    confirmBtn.style.display = 'inline-block';
  }
}

function triggerBrowse() {
  document.getElementById('file-input').click();
}

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
  localStorage.setItem('filekey_' + fileUuid, sodium.to_base64(key));
}

window.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('upload-form');
  if (!form) return;

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
        size: file.size,
        format: file.type || '-',
      },
    };

    // 3. Get auth token from LoginSessionManager (assume it exposes getAccessToken)
    const token =
      window.LoginSessionManager && window.LoginSessionManager.getAccessToken
        ? window.LoginSessionManager.getAccessToken()
        : null;
    if (!token) {
      alert('You must be logged in to upload files.');
      return;
    }

    // 4. Upload to server
    const resp = await fetch('/api/files/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + token,
      },
      body: JSON.stringify(payload),
    });

    if (resp.ok) {
      const result = await resp.json();
      const fileUuid = result.uuid;
      // 5. Store the symmetric key locally, indexed by file UUID
      storeFileKey(fileUuid, key);
      alert('File uploaded successfully!');
      window.location.href = '/view_files';
    } else {
      const msg = await resp.text();
      alert('Upload failed: ' + msg);
    }
  });
});
