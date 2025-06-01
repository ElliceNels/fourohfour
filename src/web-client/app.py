from flask import Flask, render_template, request, redirect, flash, url_for, session
from login import manage_login
from signup import validate_registration, manage_registration
from uploadfile import validate_file_size, validate_file_type
from resetpassword import manage_reset_password
from session_manager import LoginSessionManager

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def title_page():
    return render_template('title.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        account_name = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        valid, message = validate_registration(account_name, password, confirm_password)
        if not valid:
            flash(message, "error")
        else:
            registration_success, error_message = manage_registration(account_name, password)
            if registration_success:
                print(f"Registration successful for {account_name}")  
                flash(message, "success")
                return redirect(url_for('login'))
            else:
                flash(error_message, "error")
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if manage_login(password, username):
            return redirect(url_for('main_menu'))
        else:
            error = "Login failed. Please check your credentials."
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/mainmenu')
def main_menu():
    return render_template('mainmenu.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
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
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')  

        username = LoginSessionManager.getInstance().getUsername()
        
        success, message = validate_registration(
            account_name=username,
            password=new_password,
            confirm_password=confirm_password
        )
        
        if not success:
            flash(message, 'error')
            return render_template('resetpassword.html')
            
        if not old_password:
            flash('Please provide your old password', 'error')
            return render_template('resetpassword.html')
            
        # If validation passes, proceed with password reset
        success, message = manage_reset_password(old_password, new_password)
        
        if success:
            flash('Password reset successful!', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
            return render_template('resetpassword.html')
            
    return render_template('resetpassword.html')

if __name__ == '__main__':
    app.run(debug=True, port=8080)