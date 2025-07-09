import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

KEY_SIZE = 2048  # RSA key size

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[+] RSA keys generated and saved as private_key.pem and public_key.pem")

def encrypt_message(message):
    if not os.path.exists("public_key.pem"):
        print("[-] Error: public_key.pem not found. Generate keys first.")
        return

    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Save ciphertext
    with open("encrypted.bin", "wb") as f:
        f.write(ciphertext)
    print("[+] Message encrypted and saved to encrypted.bin")
    print("[+] Encrypted (base64):", base64.b64encode(ciphertext).decode())

def decrypt_file(filename):
    if not os.path.exists("private_key.pem"):
        print("[-] Error: private_key.pem not found. Generate keys first.")
        return
    if not os.path.exists(filename):
        print(f"[-] Error: {filename} not found.")
        return

    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open(filename, "rb") as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print("[+] Decrypted message:", plaintext.decode())

def decrypt_string(b64_ciphertext):
    if not os.path.exists("private_key.pem"):
        print("[-] Error: private_key.pem not found. Generate keys first.")
        return

    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    try:
        ciphertext = base64.b64decode(b64_ciphertext)
    except Exception as e:
        print("[-] Error decoding base64 ciphertext:", e)
        return

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print("[+] Decrypted message:", plaintext.decode())
    except Exception as e:
        print("[-] Error decrypting message:", e)

def main():
    parser = argparse.ArgumentParser(description="RSA Tool - Generate keys, encrypt, and decrypt messages.")
    parser.add_argument('--generate-keys', action='store_true', help="Generate RSA public/private key pair")
    parser.add_argument('--encrypt', metavar='MESSAGE', help="Encrypt a message using public_key.pem")
    parser.add_argument('--decrypt-file', metavar='FILENAME', help="Decrypt a ciphertext file using private_key.pem")
    parser.add_argument('--decrypt-string', metavar='B64_CIPHERTEXT', help="Decrypt a base64 ciphertext string")

    args = parser.parse_args()

    if args.generate_keys:
        generate_keys()
    elif args.encrypt:
        encrypt_message(args.encrypt)
    elif args.decrypt_file:
        decrypt_file(args.decrypt_file)
    elif args.decrypt_string:
        decrypt_string(args.decrypt_string)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
