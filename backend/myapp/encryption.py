from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def generate_key():
    return os.urandom(32)  # Generates a random 256-bit key

def encrypt(plain_text, key):
    iv = os.urandom(16)  # Generates a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_text).decode()  # Prepend IV for decryption

def decrypt(encrypted_text, key):
    data = base64.b64decode(encrypted_text)
    iv = data[:16]  # Extract the IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(data[16:]) + decryptor.finalize()).decode()  # Decrypt the data
