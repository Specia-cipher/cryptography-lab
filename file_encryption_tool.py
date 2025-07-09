from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import argparse

# === Helpers ===
def generate_key(password: str, salt: bytes = None) -> (bytes, bytes):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def save_key(salt: bytes, filename="file_secret.key"):
    with open(filename, "wb") as f:
        f.write(salt)
    print(f"[+] Salt saved to {filename} (keep this safe!)")

def load_key(password: str, filename="file_secret.key") -> bytes:
    with open(filename, "rb") as f:
        salt = f.read()
    key, _ = generate_key(password, salt)
    return key

# === Encryption ===
def encrypt_file(input_file: str, output_file: str, password: str):
    key, salt = generate_key(password)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(input_file, "rb") as f:
        data = f.read()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, "wb") as f:
        f.write(salt + iv + ciphertext)

    save_key(salt)
    print(f"[+] File encrypted and saved as {output_file}")

# === Decryption ===
def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, "rb") as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    key, _ = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"[+] File decrypted and saved as {output_file}")

# === CLI ===
def main():
    parser = argparse.ArgumentParser(description="AES File Encryption/Decryption Tool")
    parser.add_argument("--encrypt", metavar="FILE", help="File to encrypt")
    parser.add_argument("--decrypt", metavar="FILE", help="File to decrypt")
    parser.add_argument("--out", metavar="OUTPUT", required=True, help="Output file name")
    parser.add_argument("--password", metavar="PASSWORD", required=True, help="Password for key derivation")
    args = parser.parse_args()

    if args.encrypt:
        encrypt_file(args.encrypt, args.out, args.password)
    elif args.decrypt:
        decrypt_file(args.decrypt, args.out, args.password)
    else:
        parser.error("You must specify --encrypt or --decrypt")

if __name__ == "__main__":
    main()
