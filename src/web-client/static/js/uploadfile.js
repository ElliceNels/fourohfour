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
    // Calculate encrypted size (original + nonce + auth tag)
    const encryptedSize = file.size + 24 + 16; // XChaCha20-Poly1305 nonce (24) + auth tag (16)
    fileSize.value = `${encryptedSize} bytes (encrypted)`;

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
  localStorage.setItem(
    'filekey_' + fileUuid,
    sodium.to_base64(key, sodium.base64_variants.ORIGINAL)
  );
}

// Save keyfile to user's local disk storage
function saveKeyfileToDisk(fileUuid, key, filename) {
  const keyBase64 = sodium.to_base64(key, sodium.base64_variants.ORIGINAL);
  const keyfileContent = JSON.stringify({
    uuid: fileUuid,
    filename: filename,
    key: keyBase64,
    created: new Date().toISOString(),
    version: "1.0"
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
  input.onchange = function(event) {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = function(e) {
        try {
          const keyfileData = JSON.parse(e.target.result);
          if (keyfileData.uuid && keyfileData.key) {
            // Store key in localStorage
            localStorage.setItem('filekey_' + keyfileData.uuid, keyfileData.key);
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

// Get stored key for a file UUID
function getStoredKey(fileUuid) {
  const keyBase64 = localStorage.getItem('filekey_' + fileUuid);
  if (keyBase64) {
    return sodium.from_base64(keyBase64, sodium.base64_variants.ORIGINAL);
  }
  return null;
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
    combinedData.set(ciphertext, nonce.length);    const payload = {
      file: {
        filename: file.name,
        contents: arrayBufferToBase64(combinedData),
      },
      metadata: {
        size: combinedData.length, // Use encrypted file size (original + encryption overhead)
        format: file.type || '-',
      },
    };// 3. Upload to server (using Flask session authentication)
    const resp = await fetch('/api/files/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });    if (resp.ok) {
      const result = await resp.json();
      const fileUuid = result.uuid;
      // 4. Store the symmetric key locally, indexed by file UUID
      storeFileKey(fileUuid, key);
      
      // 5. Save keyfile to user's local disk storage
      saveKeyfileToDisk(fileUuid, key, file.name);
      
      alert('File uploaded successfully! Keyfile has been saved to your downloads folder.');
      window.location.href = '/view_files';
    } else {
      const msg = await resp.text();
      alert('Upload failed: ' + msg);
    }
  });
});
