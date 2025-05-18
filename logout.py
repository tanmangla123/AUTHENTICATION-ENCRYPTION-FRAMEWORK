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
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("✅ Logged out successfully.")
    return redirect(url_for('login'))
