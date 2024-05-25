from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def get_cipher(key):
    return Fernet(key)

def encrypt_message(cipher, message):
    return cipher.encrypt(message.encode())

def decrypt_message(cipher, encrypted_message):
    return cipher.decrypt(encrypted_message).decode()
