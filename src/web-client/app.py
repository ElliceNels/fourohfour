from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify
from utils.auth.login import manage_login
from utils.auth.signup import validate_registration, manage_registration
from utils.auth.resetpassword import manage_reset_password
from utils.files import my_files, validate_file_size, validate_file_type
from utils.auth.session_manager import LoginSessionManager
from exceptions import UserNotFoundError
from constants import GET_USER_ENDPOINT, SIGN_UP_ENDPOINT, ADD_OTPK_ENDPOINT
import time
from contextlib import suppress
from config import config
import base64
import requests
import os
import json
import hashlib

login_attempts = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300  # 5 minutes

from utils.verify_user import generate_code, save_friend

app = Flask(__name__)
app.secret_key = 'your_secret_key'
from logger import setup_logger
import logging

setup_logger()
logger = logging.getLogger(__name__)

# Directory to store encrypted keyfiles - REMOVED for security
# KEYFILES_DIR = os.path.join(os.path.dirname(__file__), 'keyfiles')
# if not os.path.exists(KEYFILES_DIR):
#     os.makedirs(KEYFILES_DIR)

# REMOVED: Keyfile storage functions - keyfiles now handled client-side only
# def get_keyfile_path(username):
# def store_encrypted_keyfile(username, keyfile_data):
# def retrieve_encrypted_keyfile(username):

@app.route('/')
def title_page():
    return render_template('title.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    clear_flashes()
    if request.method == 'POST':
        # Expect JSON payload from browser-side cryptography
        if request.is_json:
            try:
                data = request.get_json()
                account_name = data.get('username')
                public_key = data.get('public_key')
                salt = data.get('salt')
                spk = data.get('spk')
                spk_signature = data.get('spk_signature')
                otpks = data.get('otpks')
                password = data.get('password')
                # REMOVED: encrypted keyfile data is no longer stored server-side
                # encrypted_key = data.get('encrypted_key')
                # encrypted_master_key = data.get('encrypted_master_key')
            except Exception as e:
                logger.error(f"Error parsing JSON data: {str(e)}")
                return (f"Error parsing JSON data: {str(e)}", 400)
            
            with suppress(Exception):
                salt = base64.b64decode(salt)
            # API call to server-side /signup endpoint
            signup_url = config.server.url.rstrip('/') + '/sign_up'
            logger.info(f"Attempting to sign up user: {account_name}")
            logger.debug(f"Signup URL: {signup_url}")
            payload = {
                'username': account_name,
                'password': password,
                'public_key': public_key,
                'spk': spk,
                'spk_signature': spk_signature,                'salt': base64.b64encode(salt).decode() if isinstance(salt, bytes) else salt,
                'otpks': otpks
            }
            try:
                resp = requests.post(signup_url, json=payload)
            except requests.exceptions.RequestException as e:
                logger.error(f"Error during signup request: {str(e)}")
                return (f"Error during signup request: {str(e)}", 500)
            
            if resp.status_code != 200:
                return (resp.text, resp.status_code)
            
            # REMOVED: Keyfile storage - keyfiles are now handled client-side only
            # No longer storing encrypted keyfiles on the server for security
            
            session['username'] = account_name
            clear_flashes()
            flash('Registration successful!', 'success')
            return ('', 200)
        else:
            return render_template('signup.html')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    clear_flashes()
    if request.method == 'POST':
        # Accept JSON payload from browser-side cryptography
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            print(f"Login attempt for user: {username}")
            ip = request.remote_addr
            if is_rate_limited(ip):
                clear_flashes()
                flash("Too many login attempts. Please try again in 5 minutes.", "error")
                return ('Too many login attempts', 429)            # Only authenticate, do not handle cryptographic keys
            login_result = manage_login(password, username)
            record_login_attempt(ip)
            
            # Handle new return format with SPK/OTPK status
            if len(login_result) == 3:
                login_success, message, key_status = login_result
            else:
                # Fallback for old format
                login_success, message = login_result
                key_status = None
            
            if login_success:
                session['username'] = username
                clear_flashes()
                flash(message, "success")
                
                # Include SPK/OTPK status in response
                response_data = {'success': True, 'message': message}
                if key_status:
                    response_data.update(key_status)
                
                return jsonify(response_data), 200
            else:
                clear_flashes()
                flash(message, "error")
                return jsonify({'success': False, 'error': message}), 401
        else:
            # Fallback for legacy form POST (should not be used)
            return ('Invalid request', 400)
    # Only return the login page for GET requests
    return render_template('login.html')

@app.route('/mainmenu')
def main_menu():
    return render_template('mainmenu.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    LoginSessionManager.getInstance().clearSession()
    return redirect(url_for('title_page'))

@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        try:
            uploaded_file = request.files.get('file')
            
            if not uploaded_file or not uploaded_file.filename:
                flash("No file selected!", "error")
                return redirect(url_for('upload_file'))

            try:
                file_name = uploaded_file.filename
                file_type = uploaded_file.content_type
                file_data = uploaded_file.read()
                file_size = len(file_data)

                # Validate file size
                size_valid, size_error = validate_file_size(file_size)
                if not size_valid:
                    flash(size_error, "error")
                    return redirect(url_for('upload_file'))

                # Validate file type (both extension and MIME type)
                type_valid, type_error = validate_file_type(file_name, file_data)
                if not type_valid:
                    flash(type_error, "error")
                    return redirect(url_for('upload_file'))

                return render_template(
                    'uploadfile.html',
                    uploaded=True,
                    file_name=file_name,
                    file_type=file_type,
                    file_size=file_size
                )

            except Exception as e:
                flash(f"Error processing file: {str(e)}", "error")
                return redirect(url_for('upload_file'))

        except Exception as e:
            flash("An unexpected error occurred while handling the upload", "error")
            return redirect(url_for('upload_file'))

    return render_template('uploadfile.html', uploaded=False)

@app.route('/view_files')
def view_files():
    try:
        owned, shared = my_files()
        if not owned and not shared:
            logger.info("No files found for the user.")
            flash("No files found!", "info")
            return render_template('viewfiles.html', files_owned=[], files_shared=[])
    except Exception as e:
        flash(f"Error fetching files: {str(e)}", "error")
        logger.error(f"Error fetching files: {str(e)}")
        return render_template('viewfiles.html', files_owned=[], files_shared=[])
    return render_template('viewfiles.html', files_owned=owned, files_shared=shared)

@app.route('/verify_user', methods=['GET', 'POST'])
def verify_user():
    if request.method == 'POST':
        friend_username = request.form.get('friend_username')
        if not friend_username:
            flash('No friend username provided!', 'error')
            return render_template('verifyuser.html')
        try:
            logger.debug(f"Generating hash for friend: {friend_username}")
            hash_data = generate_code(friend_username)
            flash('Hash generated successfully!', 'success')
            return render_template('verifyuser.html', hash_output=hash_data)
        except Exception as e:
            flash(f'Error generating hash: {str(e)}', 'error')
            logger.error(f"Error generating hash: {str(e)}")
            return render_template('verifyuser.html')
    return render_template('verifyuser.html')

@app.route('/verify_new_user', methods=['POST'])
def verify_new_user():
    data = request.get_json()
    friend_username = data.get('friend_username') if data else None
    if not friend_username:
        logger.error('No friend username provided!')
        flash('No friend username provided!', 'error')
        return jsonify({'success': False, 'error': 'No friend username provided!'}), 400
    try:
        save_friend(friend_username)
        flash('New friend saved successfully!', 'success')
        logger.info('New friend saved successfully!')
        return jsonify({'success': True, 'message': 'New friend saved successfully!'})
    except Exception as e:
        flash(f'Error saving new friend: {str(e)}', 'error')
        logger.error(f"Error saving new friend: {str(e)}")
        return jsonify({'success': False, 'error': f'Error saving new friend: {str(e)}'}), 500

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    clear_flashes()
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')  


        if not old_password:
            clear_flashes()
            flash('Please provide your old password', 'error')
            return render_template('resetpassword.html') 


        username = session.get('username')
        if not username:
            clear_flashes()
            flash('Session expired or not logged in. Please log in again.', 'error')
            return redirect(url_for('login'))

        
        success, message = validate_registration(username, new_password, confirm_password, old_password)
        
        if not success:
            clear_flashes()
            flash(message, 'error')
            return render_template('resetpassword.html') 
            
            
        # If validation passes, proceed with password reset
        success, message = manage_reset_password(old_password, new_password)
        
        if success:
            clear_flashes()
            flash('Password reset successful!', 'success')
            return redirect(url_for('main_menu'))
        else:
            clear_flashes()
            flash(message, 'error')
            
    return render_template('resetpassword.html')


def clear_flashes():
    session.pop('_flashes', None)
@app.route('/view_file/<filename>')
def view_file(filename):
    # Placeholder for file viewing logic
    # Retrieve the file content from the server or database
    return render_template('viewfile.html', filename=filename, file_content=" This is a placeholder for file content.")

def is_rate_limited(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])
    # Remove attempts outside the window
    attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
    login_attempts[ip] = attempts
    return len(attempts) >= MAX_ATTEMPTS

def record_login_attempt(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])
    attempts.append(now)
    login_attempts[ip] = attempts

@app.route('/test_libsodium')
def test_libsodium():
    """Route to test libsodium loading"""
    return render_template('libsodium_test.html')

# REMOVED: /get_encrypted_keyfile endpoint - keyfiles are now handled client-side only
# @app.route('/get_encrypted_keyfile', methods=['POST'])
# def get_encrypted_keyfile():
#     """Endpoint to retrieve encrypted keyfile for a user during login"""
#     ...endpoint removed for security...

@app.route('/test_crypto')
def test_crypto():
    """Simple test page to verify libsodium loading"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Libsodium Test</title>
        <script src="https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.13/dist/sodium.js" 
                onerror="console.error('Failed to load libsodium from jsdelivr'); loadLibsodiumFallback();"></script>
        <script>
          function loadLibsodiumFallback() {
            console.log('Trying fallback CDN...');
            const script = document.createElement('script');
            script.src = 'https://unpkg.com/libsodium-wrappers@0.7.13/dist/sodium.js';
            script.onerror = function() {
              console.error('Failed to load libsodium from all CDNs');
              document.getElementById('result').textContent = 'FAILED: Could not load libsodium';
            };
            document.head.appendChild(script);
          }
        </script>
    </head>
    <body>
        <h1>Libsodium Test</h1>
        <div id="result">Loading...</div>
        <script>
            async function testLibsodium() {
                console.log('Testing libsodium...');
                const resultDiv = document.getElementById('result');
                
                if (typeof sodium === 'undefined') {
                    resultDiv.textContent = 'FAILED: sodium object not found';
                    return;
                }
                
                try {
                    await sodium.ready;
                    resultDiv.textContent = 'SUCCESS: libsodium loaded and ready!';
                    console.log('Libsodium version:', sodium.sodium_version_string());
                } catch (error) {
                    resultDiv.textContent = 'FAILED: ' + error;
                }
            }
            
            setTimeout(testLibsodium, 1000); // Wait 1 second for loading
        </script>
    </body>
    </html>
    '''

@app.route('/proxy_add_otpks', methods=['POST'])
def proxy_add_otpks():
    """Proxy endpoint to add OTPKs to the backend server"""
    if not request.is_json:
        return jsonify({'error': 'JSON payload required'}), 400
    
    # Check if user is logged in via Flask session
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    otpks = data.get('otpks')
    
    if not otpks:
        return jsonify({'error': 'Missing OTPKs'}), 400
    
    # Forward OTPK request to backend server using session manager tokens
    add_otpks_url = config.server.url.rstrip('/') + '/add_otpks'
    session_manager = LoginSessionManager.getInstance()
    
    try:
        # Get session tokens (returns tuple: access_token, refresh_token)
        access_token, refresh_token = session_manager.getTokens()
        if not access_token:
            return jsonify({'error': 'No valid session token'}), 401
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
        
        payload = {'otpks': otpks}
        
        resp = requests.post(add_otpks_url, json=payload, headers=headers)
        
        if resp.status_code == 201:  # Backend returns 201 for created
            return jsonify(resp.json()), 201
        else:
            logger.error(f"Backend OTPK upload failed: {resp.status_code} - {resp.text}")
            return jsonify({'error': 'Backend server error'}), resp.status_code
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error forwarding OTPK request: {str(e)}")
        return jsonify({'error': 'Request failed'}), 500

@app.route('/proxy_update_spk', methods=['POST'])
def proxy_update_spk():
    """Proxy endpoint to update SPK on the backend server"""
    if not request.is_json:
        return jsonify({'error': 'JSON payload required'}), 400
    
    # Check if user is logged in via Flask session
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    spk = data.get('spk')
    spk_signature = data.get('spk_signature')
    
    if not spk or not spk_signature:
        return jsonify({'error': 'Missing SPK or signature'}), 400
    
    # Forward SPK update request to backend server using session manager tokens
    update_spk_url = config.server.url.rstrip('/') + '/update_spk'
    session_manager = LoginSessionManager.getInstance()
    
    try:
        # Get session tokens (returns tuple: access_token, refresh_token)
        access_token, refresh_token = session_manager.getTokens()
        if not access_token:
            return jsonify({'error': 'No valid session token'}), 401
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
        
        payload = {
            'spk': spk,
            'spk_signature': spk_signature
        }
        
        resp = requests.post(update_spk_url, json=payload, headers=headers)
        
        if resp.status_code == 200:
            return jsonify(resp.json()), 200
        else:
            logger.error(f"Backend SPK update failed: {resp.status_code} - {resp.text}")
            return jsonify({'error': 'Backend server error'}), resp.status_code
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error forwarding SPK update: {str(e)}")
        return jsonify({'error': 'Request failed'}), 500

# Proxy endpoint for file upload
@app.route('/api/files/upload', methods=['POST'])
def proxy_file_upload():
    """Proxy endpoint to upload files to the backend server"""
    if not request.is_json:
        return jsonify({'error': 'JSON payload required'}), 400
    
    # Check if user is logged in via Flask session
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    
    # Validate required fields
    if not data or 'file' not in data or 'metadata' not in data:
        return jsonify({'error': 'Missing file or metadata'}), 400
    
    file_data = data['file']
    metadata = data['metadata']
    
    if not file_data.get('filename') or not file_data.get('contents'):
        return jsonify({'error': 'Missing filename or contents'}), 400
      # Forward file upload request to backend server using session manager tokens
    upload_url = config.server.url.rstrip('/') + '/api/files/upload'
    session_manager = LoginSessionManager.getInstance()
    
    try:
        # Get session tokens (returns tuple: access_token, refresh_token)
        access_token, refresh_token = session_manager.getTokens()
        if not access_token:
            return jsonify({'error': 'No valid session token'}), 401
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
        
        # Forward the exact payload from the client
        resp = requests.post(upload_url, json=data, headers=headers)
        
        if resp.status_code == 201:  # Backend returns 201 for created
            return jsonify(resp.json()), 201
        else:
            logger.error(f"Backend file upload failed: {resp.status_code} - {resp.text}")
            return jsonify({'error': 'Backend server error'}), resp.status_code
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error forwarding file upload: {str(e)}")
        return jsonify({'error': 'Request failed'}), 500

if __name__ == '__main__':
    app.run(host=config.server.host, port=config.server.port, debug=config.server.debug)