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
    
    private_key, public_key = generate_keys()

    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    print("Public Key (PEM):\n", public_key_pem.decode())
    print("Private Key (PEM):\n", private_key_pem.decode())

    
    message = "This is a test message."
    print("Message to Encrypt:", message)
    
   
    ciphertext = encrypt_message(public_key, message)
    print("Encrypted Message:", ciphertext)

    
    decrypted_message = decrypt_message(private_key, ciphertext)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
