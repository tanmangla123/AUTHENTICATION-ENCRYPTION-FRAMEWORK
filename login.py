from flask import Flask, render_template, request, redirect, url_for, flash, session
import base64
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"

UPLOAD_FOLDER = "uploads"
RESULT_FOLDER = "static"
KEY_FOLDER = "keys"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'user' and password == 'digital123':
            session['user'] = username
            flash("✅ Logged in successfully!")
            return redirect(url_for('index'))
        else:
            flash("❌ Invalid credentials.")
            return render_template('login.html')
    return render_template('login.html')
