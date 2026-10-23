from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import secrets

app = Flask(__name__)
app.secret_key = "2B7E151628AED2A6ABF7158809CF4F3C"

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"
SECRET_KEY = secrets.token_bytes(16)  # 16-byte AES key

# Ensure directories exist
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

@app.route("/")
def home():
    return render_template("index2.html")

@app.route("/file-upload", methods=["POST"])
def file_upload():
    if "file" in request.files:
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file!", "danger")
            return redirect(url_for("home"))

        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename + ".enc")
        file.save(filepath)

        method = request.form.get("encryption_method", "CBC")

        if method == "TRIPLE":
            triple_encrypt_file(filepath, encrypted_path, SECRET_KEY)
        else:
            encrypt_file(filepath, encrypted_path, SECRET_KEY, method)

        flash(f"File '{filename}' encrypted using {method}!", "success")
    return redirect(url_for("home"))

@app.route("/file-decrypt", methods=["POST"])
def file_decrypt():
    filename = request.form.get("decrypt_file")
    if not filename:
        flash("No file specified for decryption!", "danger")
        return redirect(url_for("home"))

    method = request.form.get("decryption_method", "CBC")
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename)
    decrypted_path = os.path.join(DECRYPTED_FOLDER, filename.replace(".enc", ""))

    if os.path.exists(encrypted_path):
        if method == "TRIPLE":
            triple_decrypt_file(encrypted_path, decrypted_path, SECRET_KEY)
        else:
            decrypt_file(encrypted_path, decrypted_path, SECRET_KEY, method)
        return send_file(decrypted_path, as_attachment=True)
    else:
        flash(f"Encrypted file '{filename}' not found!", "danger")
        return redirect(url_for("home"))

@app.route("/text-encrypt", methods=["POST"])
def text_encrypt():
    text = request.form.get("text_input", "")
    method = request.form.get("encryption_method", "CBC")

    if method == "TRIPLE":
        encrypted_text = triple_encrypt_text(text, SECRET_KEY)
    else:
        encrypted_text = encrypt_text(text, SECRET_KEY, method)

    return render_template("index2.html", encrypted_text=encrypted_text)

@app.route("/text-decrypt", methods=["POST"])
def text_decrypt():
    text = request.form.get("text_input", "")
    method = request.form.get("decryption_method", "CBC")

    try:
        if method == "TRIPLE":
            decrypted_text = triple_decrypt_text(text, SECRET_KEY)
        else:
            decrypted_text = decrypt_text(text, SECRET_KEY, method)
        return render_template("index2.html", decrypted_text=decrypted_text)
    except Exception as e:
        flash("Decryption failed!", "danger")
        return redirect(url_for("home"))

# --------------------- Encryption Utilities ---------------------

def encrypt_file(input_path, output_path, key, method):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv) if method == "CBC" else modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(iv + encrypted if method == "CBC" else encrypted)

def decrypt_file(input_path, output_path, key, method):
    with open(input_path, 'rb') as f:
        iv = f.read(16) if method == "CBC" else b""
        data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv) if method == "CBC" else modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(padded) + unpadder.finalize()

    with open(output_path, 'wb') as f:
        f.write(decrypted)

def triple_encrypt_file(input_path, output_path, key):
    temp_path = output_path + ".tmp1"
    encrypt_file(input_path, temp_path, key, "CBC")
    temp_path2 = output_path + ".tmp2"
    encrypt_file(temp_path, temp_path2, key, "ECB")
    encrypt_file(temp_path2, output_path, key, "CBC")
    os.remove(temp_path)
    os.remove(temp_path2)

def triple_decrypt_file(input_path, output_path, key):
    temp_path1 = output_path + ".tmp1"
    temp_path2 = output_path + ".tmp2"
    decrypt_file(input_path, temp_path2, key, "CBC")
    decrypt_file(temp_path2, temp_path1, key, "ECB")
    decrypt_file(temp_path1, output_path, key, "CBC")
    os.remove(temp_path1)
    os.remove(temp_path2)

# --------------------- Text Utilities ---------------------

def encrypt_text(text, key, method):
    iv = os.urandom(16) if method == "CBC" else b""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv) if method == "CBC" else modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode()) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return (iv + encrypted).hex() if method == "CBC" else encrypted.hex()

def decrypt_text(text, key, method):
    data = bytes.fromhex(text)
    iv = data[:16] if method == "CBC" else b""
    encrypted = data[16:] if method == "CBC" else data

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv) if method == "CBC" else modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

def triple_encrypt_text(text, key):
    first = encrypt_text(text, key, "CBC")
    second = encrypt_text(bytes.fromhex(first).decode('latin1'), key, "ECB")
    final = encrypt_text(bytes.fromhex(second).decode('latin1'), key, "CBC")
    return final

def triple_decrypt_text(text, key):
    first = decrypt_text(text, key, "CBC")
    second = decrypt_text(first.encode('latin1').hex(), key, "ECB")
    final = decrypt_text(second.encode('latin1').hex(), key, "CBC")
    return final

# --------------------- Run Server ---------------------

if __name__ == "__main__":
    app.run(debug=True, port=5001)
