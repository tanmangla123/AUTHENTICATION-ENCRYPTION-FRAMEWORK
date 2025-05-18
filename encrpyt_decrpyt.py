@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
def encrypt_decrypt():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        mode = request.form['mode']
        file = request.files['file']
        user_key = request.form.get('key', '')

        if not file or not user_key:
            flash("Please upload a file and enter a key.")
            return redirect(url_for('encrypt_decrypt'))

        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        with open(file_path, "rb") as f:
            file_data = f.read()

        if mode == 'encrypt':
            encrypted_data = xor_encrypt(file_data, user_key)
            output_filename = f"encrypted_{filename}"
        else:
            encrypted_data = xor_decrypt(file_data, user_key)
            output_filename = f"decrypted_{filename}"

        out_path = os.path.join(RESULT_FOLDER, output_filename)

        with open(out_path, "wb") as out_file:
            out_file.write(encrypted_data)

        flash(f"✅ File {mode}ed successfully!")
        return render_template("encrypt_decrypt.html", download_link=url_for('static', filename=output_filename))

    return render_template("encrypt_decrypt.html")
