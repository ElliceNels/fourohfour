from flask import Flask, render_template, request, redirect, flash, url_for
from signup import validate_registration, manage_registration

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def title_page():
    return render_template('title.html')

@app.route('/login')
def login():
    return render_template('login.html')

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
            manage_registration(account_name, password)
            flash(message, "success")
            return redirect(url_for('login'))
    

    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)