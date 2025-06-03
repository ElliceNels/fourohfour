from flask import Flask, render_template, request, redirect, flash, url_for, session
from login import manage_login
from signup import validate_registration, manage_registration
from uploadfile import validate_file_size, validate_file_type
from resetpassword import manage_reset_password
from session_manager import LoginSessionManager
from exceptions import UserNotFoundError
from constants import GET_USER_ENDPOINT

app = Flask(__name__)
app.secret_key = 'your_secret_key'

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

        clear_flashes()
        flash("Logging in", "info")

        login_success, message = manage_login(password, username)
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
    return render_template('viewfiles.html', owned_files=[], shared_files=[])

@app.route('/verify_user')
def verify_user():
    return render_template("verifyuser.html")

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

if __name__ == '__main__':
    app.run(debug=True, port=8080)