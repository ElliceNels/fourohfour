from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify
from utils.auth.login import manage_login
from utils.auth.signup import validate_registration, manage_registration
from utils.auth.resetpassword import manage_reset_password
from utils.files import my_files, validate_file_size, validate_file_type
from utils.auth.session_manager import LoginSessionManager
from exceptions import UserNotFoundError
from constants import GET_USER_ENDPOINT
import time
from config import config

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

@app.route('/')
def title_page():
    return render_template('title.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    clear_flashes()
    if request.method == 'POST':
        account_name = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        valid, message = validate_registration(account_name, password, confirm_password)
        if not valid:
            clear_flashes()
            flash(message, "error")
        else:
            registration_success, error_message = manage_registration(account_name, password)
            if registration_success:
                session['username'] = account_name
                print(f"Registration successful for {account_name}")  
                clear_flashes()
                flash(message, "success")
                return redirect(url_for('main_menu'))
            else:
                clear_flashes()
                flash(error_message, "error")
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    clear_flashes()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip = request.remote_addr

        if is_rate_limited(ip):
            clear_flashes()
            flash("Too many login attempts. Please try again in 5 minutes.", "error")
            return render_template('login.html')
        
        login_success, message = manage_login(password, username)
        record_login_attempt(ip) 
        if login_success:
            session['username'] = username
            print(f"Login successful for {username}")
            clear_flashes()
            flash(message, "success")
            return redirect(url_for('main_menu'))
        else:
            clear_flashes()
            flash(message, "error")
            
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

if __name__ == '__main__':
    app.run(host=config.server.host, port=config.server.port, debug=True)