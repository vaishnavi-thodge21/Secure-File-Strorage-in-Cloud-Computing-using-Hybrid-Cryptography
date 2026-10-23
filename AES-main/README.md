"""
Flask AES File Encryption and Decryption App
--------------------------------------------

This application allows users to upload files for encryption and decryption using AES (Advanced Encryption Standard).
The encryption process ensures data security by transforming files into a secure format, requiring the correct key to decrypt.

How It Works:
1. **Key Management:**
   - The application generates a 16-byte AES key (or loads it from 'secret.key' if it already exists).
   - This key is used for both encryption and decryption to maintain consistency.

2. **Uploading and Encrypting a File:**
   - Users can upload a file through a web form.
   - The file is saved in the 'uploads' directory.
   - It is then encrypted using AES in CBC mode, with a randomly generated IV (Initialization Vector).
   - The encrypted file (IV + ciphertext) is stored in the 'encrypted' directory with a `.enc` extension.

3. **Decrypting a File:**
   - Users provide the filename they wish to decrypt.
   - The system checks if the encrypted file exists.
   - The decryption function retrieves the IV, decrypts the file using the stored AES key, and removes padding.
   - The decrypted file is saved in the 'decrypted' directory and is available for download.

4. **Flask Web Routes:**
   - `/` -> Renders the file upload and decrypt form (`index2.html`).
   - `/file-upload` -> Handles file upload and encryption.
   - `/file-decrypt` -> Handles file decryption and allows users to download the decrypted file.

Security Considerations:
- The AES key is stored in a file ('secret.key') to ensure consistency across sessions.
- IV (Initialization Vector) is used to add randomness to encryption, preventing pattern-based attacks.
- PKCS7 padding ensures that the data aligns with AES block sizes.

This project provides a simple but secure implementation of file encryption and decryption using Flask.
"""
//run following cmd
pip install -r requirements.txt
pip install flask
pip install cryptography
python app.py


//to create python

python -m venv venv
