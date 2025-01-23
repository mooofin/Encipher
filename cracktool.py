import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from base64 import b64encode, b64decode

# Constants
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
BLOCK_SIZE = 128

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a cryptographic key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(data: bytes, password: str) -> str:
    """Encrypts the data with the given password."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return b64encode(salt + iv + encrypted_data).decode()

def decrypt(token: str, password: str) -> bytes:
    """Decrypts the token with the given password."""
    raw_data = b64decode(token)
    salt, iv, encrypted_data = raw_data[:SALT_SIZE], raw_data[SALT_SIZE:SALT_SIZE+16], raw_data[SALT_SIZE+16:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(decrypted_padded_data) + unpadder.finalize()

def main():
    parser = argparse.ArgumentParser(description="A simple encryption tool.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt.")
    parser.add_argument("input", help="Input file path or text.")
    parser.add_argument("output", help="Output file path.")
    parser.add_argument("password", help="Password for encryption/decryption.")
    args = parser.parse_args()

    try:
        if args.mode == "encrypt":
            with open(args.input, "rb") as f:
                plaintext = f.read()
            encrypted_data = encrypt(plaintext, args.password)
            with open(args.output, "w") as f:
                f.write(encrypted_data)
            print("Encryption successful!")

        elif args.mode == "decrypt":
            with open(args.input, "r") as f:
                encrypted_data = f.read()
            plaintext = decrypt(encrypted_data, args.password)
            with open(args.output, "wb") as f:
                f.write(plaintext)
            print("Decryption successful!")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
