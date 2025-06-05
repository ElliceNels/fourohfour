# Web Client Libsodium-js Migration

## Overview

Successfully migrated the web client from TweetNaCl-js and Web Crypto API to libsodium-js for consistency with the desktop client's cryptographic operations. Additionally implemented server-side encrypted keyfile storage to enable cross-device access.

## Changes Made

### 1. HTML Templates Updated

- **signup.html**: Replaced TweetNaCl CDN links with libsodium-js (skypack CDN)
- **login.html**: Added libsodium-js script include (skypack CDN)
- **uploadfile.html**: Added libsodium-js script include (skypack CDN)

### 2. JavaScript Cryptographic Functions Migrated

#### signup.js

- **Key Generation**: Replaced TweetNaCl `nacl.sign.keyPair()` with libsodium `sodium.crypto_sign_keypair()`
- **Password Derivation**: Replaced Web Crypto PBKDF2 with Argon2id `sodium.crypto_pwhash()`
- **Encryption**: Replaced AES-GCM with XChaCha20-Poly1305 `sodium.crypto_aead_xchacha20poly1305_ietf_encrypt()`
- **Data Format**: Now uses desktop client format `[nonce][ciphertext]`
- **Storage**: **UPDATED** - Now sends encrypted keyfile to server instead of localStorage

#### login.js

- **Password Derivation**: Migrated to Argon2id matching signup
- **Decryption**: Updated to use XChaCha20-Poly1305 with desktop client data format
- **Key Loading**: **UPDATED** - Now retrieves encrypted keyfile from server instead of localStorage

#### uploadfile.js

- **File Encryption**: Migrated from AES-GCM to XChaCha20-Poly1305
- **Key Generation**: Now uses libsodium random key generation
- **Data Format**: Uses desktop client compatible `[nonce][ciphertext]` format
- **Error Handling**: Enhanced libsodium initialization with proper error checking

### 3. Server-Side Keyfile Storage Implementation

#### Flask App Updates (app.py)

- **New Endpoint**: `/get_encrypted_keyfile` POST endpoint for retrieving encrypted keyfiles
- **Modified Endpoint**: `/signup` now accepts and stores encrypted keyfile data
- **Storage Directory**: Created `keyfiles/` directory for server-side encrypted keyfile storage
- **Security**: Keyfiles stored as encrypted JSON, identified by username hash

#### Storage Architecture

- **Previous**: localStorage in browser (device-specific)
- **Current**: Server-side JSON files in `keyfiles/` directory (cross-device accessible)
- **Format**: `{username_hash}.json` containing encrypted keyfile data
- **Benefits**: Cross-device login capability, persistent storage

### 4. CDN Resolution

- **Issue**: jsdelivr and unpkg CDNs had loading reliability issues
- **Solution**: Switched to skypack CDN (`https://cdn.skypack.dev/libsodium-wrappers@^0.7.11`)
- **Result**: Reliable libsodium-js loading across all HTML templates

### 3. Cryptographic Parameters

All parameters now match the desktop client:

- **Key Derivation**: Argon2id with INTERACTIVE limits
- **Encryption**: XChaCha20-Poly1305 AEAD
- **Salt Size**: 16 bytes
- **Key Size**: 32 bytes
- **Nonce Size**: 24 bytes (XChaCha20-Poly1305)

### 4. Data Format Consistency

- Encrypted data follows desktop pattern: `[nonce][ciphertext]`
- Base64 encoding for storage and transmission
- Compatible with desktop client's file formats

### 5. Testing

Created `test_crypto.html` to verify:

- Libsodium-js initialization
- Ed25519 key generation
- Argon2id password derivation
- XChaCha20-Poly1305 encryption/decryption
- Format compatibility with desktop client
- Cryptographic consistency

## Migration Benefits

1. **Consistency**: Web and desktop clients now use identical cryptographic primitives
2. **Security**: Upgraded from PBKDF2 to Argon2id, AES-GCM to XChaCha20-Poly1305
3. **Compatibility**: Encrypted data can be shared between web and desktop clients
4. **Standards**: Uses modern, recommended cryptographic algorithms

## Usage Instructions

1. **Signup Process**:

   - Generates Ed25519 identity keypair
   - Derives master key using Argon2id
   - Encrypts keys with XChaCha20-Poly1305
   - **NEW**: Sends encrypted keyfile to server for storage

2. **Login Process**:

   - **NEW**: Retrieves encrypted keyfile from server by username
   - Derives key using same Argon2id parameters
   - Decrypts master key for session use

3. **File Upload**:
   - Generates random XChaCha20-Poly1305 key per file
   - Encrypts file client-side
   - Stores decryption key locally
   - Uploads encrypted data to server

## Server-Side Storage Details

### Keyfile Storage

- **Location**: `keyfiles/` directory in web client
- **Naming**: `{username_hash}.json` (SHA-256 hash of username)
- **Format**: JSON containing encrypted keyfile data
- **Security**: Files remain encrypted, server cannot decrypt without user password

### Cross-Device Benefits

- Users can log in from any device
- No dependency on browser localStorage
- Persistent storage survives browser data clearing
- Simplified account recovery process

## Compatibility Notes

- All new accounts will use libsodium-js format with server-side storage
- Existing TweetNaCl accounts would need migration from localStorage to server
- Desktop and web clients now have cryptographic compatibility
- Server remains agnostic to encryption implementation (stores encrypted data only)
- **Cross-platform**: Users can access accounts from web and desktop clients

## Files Modified

- `templates/signup.html` - Updated CDN, libsodium-js integration
- `templates/login.html` - Updated CDN, libsodium-js integration
- `templates/uploadfile.html` - Updated CDN, libsodium-js integration
- `static/js/signup.js` - Complete rewrite for libsodium-js + server storage
- `static/js/login.js` - Updated for libsodium-js + server retrieval
- `static/js/uploadfile.js` - Updated for libsodium-js + enhanced error handling
- `app.py` - Added keyfile storage endpoints
- `keyfiles/` - New directory for server-side encrypted keyfile storage
- `config.json` - Updated to localhost:4004 for local testing

## Testing Status

- ✅ Libsodium-js CDN loading resolved (skypack)
- ✅ Cryptographic functions migrated
- ✅ Server-side storage implementation complete
- ✅ Error handling enhanced
- 🔄 **Pending**: End-to-end signup/login flow testing
