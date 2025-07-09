#!/usr/bin/env python3

import argparse
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("rsa_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("rsa_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[+] RSA key pair generated: rsa_private.pem, rsa_public.pem")

def encrypt_file(input_file, output_file, pubkey_file, base64_output=False):
    # Load RSA public key
    with open(pubkey_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Generate random AES key and IV
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)       # 16 bytes for CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad and encrypt the file
    with open(input_file, "rb") as f:
        data = f.read()
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt AES key with RSA public key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save outputs
    with open(output_file, "wb") as f:
        f.write(iv + encrypted_data)
    with open("key.enc", "wb") as f:
        f.write(encrypted_key)

    if base64_output:
        b64_key = base64.b64encode(encrypted_key).decode()
        b64_data = base64.b64encode(iv + encrypted_data).decode()
        with open(output_file + ".b64", "w") as f:
            f.write(f"{b64_key}:{b64_data}")
        print(f"[+] Base64 bundle saved to {output_file}.b64")

    print(f"[+] File encrypted: {output_file}")
    print("[+] Encrypted AES key saved: key.enc")

def decrypt_file(input_file, output_file, privkey_file, base64_input=False):
    # Load RSA private key
    with open(privkey_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    if base64_input:
        with open(input_file, "r") as f:
            b64_key, b64_data = f.read().split(":")
        encrypted_key = base64.b64decode(b64_key)
        encrypted_data = base64.b64decode(b64_data)
    else:
        with open("key.enc", "rb") as f:
            encrypted_key = f.read()
        with open(input_file, "rb") as f:
            encrypted_data = f.read()

    # Decrypt AES key with RSA private key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Extract IV and decrypt data
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_len = padded_data[-1]
    data = padded_data[:-padding_len]

    with open(output_file, "wb") as f:
        f.write(data)

    print(f"[+] File decrypted: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Hybrid Encryption Tool (AES + RSA)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate-keys", action="store_true", help="Generate RSA key pair")
    group.add_argument("--encrypt", metavar="FILE", help="Encrypt file")
    group.add_argument("--decrypt", metavar="FILE", help="Decrypt file")
    parser.add_argument("--out", metavar="FILE", help="Output file")
    parser.add_argument("--pubkey", metavar="FILE", help="RSA public key (for encryption)")
    parser.add_argument("--privkey", metavar="FILE", help="RSA private key (for decryption)")
    parser.add_argument("--base64", action="store_true", help="Enable Base64 encoding/decoding")

    args = parser.parse_args()

    if args.generate_keys:
        generate_rsa_keys()
    elif args.encrypt:
        if not args.pubkey or not args.out:
            print("[-] Encryption requires --pubkey and --out")
            return
        encrypt_file(args.encrypt, args.out, args.pubkey, args.base64)
    elif args.decrypt:
        if not args.privkey or not args.out:
            print("[-] Decryption requires --privkey and --out")
            return
        decrypt_file(args.decrypt, args.out, args.privkey, args.base64)

if __name__ == "__main__":
    main()
