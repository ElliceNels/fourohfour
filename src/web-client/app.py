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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload_file')
def upload_file():
    # Your upload file logic
    return "Upload File Page"

@app.route('/view_files')
def view_files():
    # Your view files logic
    return "View Files Page"

@app.route('/verify_user')
def verify_user():
    # Your verify user logic
    return "Verify User Page"

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # You can render a reset password page or just a placeholder for now
    return "Reset Password Page"

if __name__ == '__main__':
    app.run(debug=True)