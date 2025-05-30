from flask import Flask, render_template, request, redirect, flash, url_for, session
from signup import validate_registration

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
            flash(message, "success")
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return redirect(url_for('main_menu'))
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
        uploaded_file = request.files.get('file')
        if uploaded_file and uploaded_file.filename:
            file_name = uploaded_file.filename
            file_type = uploaded_file.content_type
            file_data = uploaded_file.read()
            file_size = len(file_data)

            return render_template(
                'uploadfile.html',
                uploaded=True,
                file_name=file_name,
                file_type=file_type,
                file_size=file_size
            )
        else:
            flash("No file selected!", "error")
            return redirect(url_for('upload_file'))

    return render_template('uploadfile.html', uploaded=False)

@app.route('/view_files')
def view_files():
    return "View Files Page"

@app.route('/verify_user')
def verify_user():
    return "Verify User Page"

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        pass
    return render_template('resetpassword.html')

if __name__ == '__main__':
    app.run(debug=True)