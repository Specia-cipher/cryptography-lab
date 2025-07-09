from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
import base64
import argparse
import sys

# Generate ECC keys
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Save private key
    with open("ecc_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("ecc_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[+] ECC keys generated and saved as ecc_private_key.pem and ecc_public_key.pem")

# Fix base64 padding
def fix_base64_padding(b64_string):
    return b64_string + "=" * (-len(b64_string) % 4)

# Sign a message
def sign_message(message):
    try:
        with open("ecc_private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print("[-] Private key file not found. Generate keys first.")
        sys.exit(1)

    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    # Save signature to .sig (binary)
    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("[+] Signature saved to signature.sig")

    # Save signature to .b64 (base64)
    signature_b64 = base64.b64encode(signature).decode()
    with open("signature.b64", "w") as f:
        f.write(signature_b64)
    print("[+] Signature saved to signature.b64")

    print(f"[+] Signature (base64): {signature_b64}")

# Verify signature from file
def verify_signature_file(message, signature_file):
    try:
        with open("ecc_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("[-] Public key file not found. Generate keys first.")
        sys.exit(1)

    try:
        with open(signature_file, "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        print(f"[-] Signature file '{signature_file}' not found.")
        sys.exit(1)

    try:
        public_key.verify(
            signature,
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        print("[+] Signature from file is valid!")
    except InvalidSignature:
        print("[-] Invalid signature (file).")

# Verify signature from base64 string
def verify_signature_base64(message, signature_b64):
    try:
        with open("ecc_public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("[-] Public key file not found. Generate keys first.")
        sys.exit(1)

    try:
        padded_b64 = fix_base64_padding(signature_b64)
        signature = base64.b64decode(padded_b64)
        public_key.verify(
            signature,
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        print("[+] Signature from base64 string is valid!")
    except (InvalidSignature, ValueError, base64.binascii.Error):
        print("[-] Invalid signature (base64).")

def main():
    parser = argparse.ArgumentParser(description="ECC Tool - Key generation, message signing, and signature verification.")
    parser.add_argument('--generate-keys', action='store_true', help="Generate ECC key pair")
    parser.add_argument('--sign', help="Sign a message")
    parser.add_argument('--verify-file', nargs=2, metavar=('message', 'signature_file'), help="Verify message with signature file")
    parser.add_argument('--verify-base64', nargs=2, metavar=('message', 'base64_signature'), help="Verify message with base64 signature")

    args = parser.parse_args()

    if args.generate_keys:
        generate_keys()
    elif args.sign:
        sign_message(args.sign)
    elif args.verify_file:
        verify_signature_file(args.verify_file[0], args.verify_file[1])
    elif args.verify_base64:
        verify_signature_base64(args.verify_base64[0], args.verify_base64[1])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
