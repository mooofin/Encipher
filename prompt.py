from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.PKCS1v15()
    )
    return ciphertext


def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )
    return plaintext.decode()


def main():
    print("RSA Encryption and Decryption Program")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Exit")

    choice = input("Enter your choice: ").strip()

    if choice == "1":
        # Generate RSA keys
        private_key, public_key = generate_keys()

        # Serialize and save the private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("private_key.pem", "wb") as key_file:
            key_file.write(private_key_pem)

        print("\nPrivate key saved to 'private_key.pem' (KEEP IT SAFE!)")

        # Serialize and save the public key
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("public_key.pem", "wb") as pub_key_file:
            pub_key_file.write(public_key_pem)

        print("Public key saved to 'public_key.pem'.")

        # Get the message to encrypt
        message = input("\nEnter the message to encrypt: ").strip()
        ciphertext = encrypt_message(public_key, message)

        # Save ciphertext to a file
        with open("ciphertext.bin", "wb") as file:
            file.write(ciphertext)

        print("\nEncrypted message saved to 'ciphertext.bin'.")

    elif choice == "2":
        # Load private key
        try:
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
        except FileNotFoundError:
            print("\nPrivate key file not found. Please encrypt a message first.")
            return

        # Load ciphertext from the file
        try:
            with open("ciphertext.bin", "rb") as file:
                ciphertext = file.read()
        except FileNotFoundError:
            print("\nCiphertext file not found. Please encrypt a message first.")
            return

        # Decrypt the message
        try:
            plaintext = decrypt_message(private_key, ciphertext)
            print("\nDecrypted Message:", plaintext)
        except ValueError as e:
            print("\nDecryption failed: Incorrect key or ciphertext.")
        except Exception as e:
            print("\nDecryption failed:", str(e))

    elif choice == "3":
        print("Exiting.")
        return
    else:
        print("\nInvalid choice. Please try again.")


if __name__ == "__main__":
    main()
