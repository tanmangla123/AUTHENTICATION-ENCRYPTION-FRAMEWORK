from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = "your_secret_key"

UPLOAD_FOLDER = "uploads"
RESULT_FOLDER = "static"
KEY_FOLDER = "keys"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

# =============== Basic Hashing ===============
def simple_hash(data):
    hash_val = 0
    for byte in data:
        hash_val = (hash_val * 31 + byte) % (10**9 + 7)
    return hash_val

# ============ RSA Public Key Loading ============
def load_rsa_public_key(pem_path):
    with open(pem_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    public_numbers = public_key.public_numbers()
    return public_numbers.n, public_numbers.e

# ============ RSA Private Key Loading ============
def load_rsa_private_key(pem_path):
    with open(pem_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    private_numbers = private_key.private_numbers()
    return private_numbers

# =============== XOR Encryption ===============
def xor_encrypt(data, key):
    key_bytes = key.encode()
    return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

def xor_decrypt(data, key):
    return xor_encrypt(data, key)

# =============== Login ===============
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

# =============== Logout ===============
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("✅ Logged out successfully.")
    return redirect(url_for('login'))

# =============== Home Page ===============
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

# ============ Sign Verification (with Sign / Verify tabs) ============
@app.route('/sign_verification', methods=['GET', 'POST'])
def sign_verification():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'sign':
            # Sign file
            file = request.files.get('file')
            user_key = request.form.get('key')

            if not file or not user_key:
                flash("Please upload a file and enter a key to sign.","sign")
                return redirect(url_for('sign_verification'))

            file_data = file.read()
            hashed = simple_hash(file_data)

            try:
                private_key_obj = load_rsa_private_key(os.path.join(KEY_FOLDER, "private.pem"))
                d = private_key_obj.d
                n = private_key_obj.public_numbers.n

                signature_int = pow(hashed, d, n)
                sig_bytes = signature_int.to_bytes((signature_int.bit_length() + 7) // 8, byteorder='big')

                sig_filename = f"{file.filename}.sig"
                sig_path = os.path.join(RESULT_FOLDER, sig_filename)
                with open(sig_path, "wb") as sig_file:
                    sig_file.write(sig_bytes)

                flash(f"✅ File signed successfully! Download signature below.","sign")
                return render_template('sign_verification.html', active_tab='sign', sign_download=url_for('static', filename=sig_filename))

            except Exception as e:
                flash(f"❌ Signing failed: {str(e)}","sign")
                return redirect(url_for('sign_verification'))

        elif action == 'verify':
            # Verify signature
            file = request.files.get('file')
            signature = request.files.get('signature')

            if not file or not signature:
                flash("Please upload both the file and its signature.","sign")
                return redirect(url_for('sign_verification'))

            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            signature_path = os.path.join(UPLOAD_FOLDER, signature.filename)

            file.save(file_path)
            signature.save(signature_path)

            try:
                n, e = load_rsa_public_key(os.path.join(KEY_FOLDER, "public.pem"))

                with open(file_path, "rb") as f:
                    file_data = f.read()
                with open(signature_path, "rb") as s:
                    sig_data = s.read()

                hashed = simple_hash(file_data)
                sig_int = int.from_bytes(sig_data, 'big')
                decrypted = pow(sig_int, e, n)

                if decrypted == hashed:
                    flash("✅ Signature is VALID!","sign")
                else:
                    flash("❌ Signature is INVALID!","sign")

            except Exception as err:
                flash(f"❌ Verification failed: {err}","sign")

            return redirect(url_for('sign_verification'))

    # GET request
    return render_template('sign_verification.html', active_tab='sign')

# ========== File Encryption / Decryption ==========
@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
def encrypt_decrypt():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        mode = request.form['mode']
        file = request.files['file']
        user_key = request.form.get('key', '')

        if not file or not user_key:
            flash("Please upload a file and enter a key.","enc")
            return redirect(url_for('encrypt_decrypt'))

        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        with open(file_path, "rb") as f:
            file_data = f.read()
        #after reading file_data
        stat = os.stat(file_path)
        metadata = {
        "Filename": filename,
        "Size (bytes)": stat.st_size,
        "Created": time.ctime(stat.st_ctime),
        "Last Modified": time.ctime(stat.st_mtime),
        }

        magic_header = b'DIGITAL::'

        if mode == 'encrypt':
            # Add header before encryption
            encrypted_data = xor_encrypt(magic_header + file_data, user_key)
            output_filename = f"encrypted_{filename}"
        else:
            # Decrypt the file first
            decrypted_data = xor_decrypt(file_data, user_key)
            if not decrypted_data.startswith(magic_header):
                flash("❌ Decryption failed. Wrong key or corrupted file.","enc")
                return redirect(url_for('encrypt_decrypt'))

            # Remove header
            encrypted_data = decrypted_data[len(magic_header):]
            output_filename = f"decrypted_{filename}"

        out_path = os.path.join(RESULT_FOLDER, output_filename)

        with open(out_path, "wb") as out_file:
            out_file.write(encrypted_data)

        flash(f"✅ File {mode}ed successfully!","enc")
        return render_template("encrypt_decrypt.html", download_link=url_for('static', filename=output_filename),metadata=metadata)

    # GET request
    return render_template("encrypt_decrypt.html")
if __name__ == "__main__":
    app.run(debug=True)
