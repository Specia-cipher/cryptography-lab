# ecc_sign_tool.py
# ECC Digital Signature Tool for signing and verifying messages

import argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import base64

# Generate ECC key pair
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()

    with open("ecc_sign_private_key.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("ecc_sign_public_key.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[+] ECC signing keys generated and saved as ecc_sign_private_key.pem and ecc_sign_public_key.pem")

# Sign a message
def sign_message(message):
    with open("ecc_sign_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    # Save signature
    with open("ecc_signature.sig", "wb") as sig_file:
        sig_file.write(signature)
    with open("ecc_signature.b64", "w") as b64_file:
        b64_file.write(base64.b64encode(signature).decode())

    print("[+] Signature saved to ecc_signature.sig and ecc_signature.b64")
    print("[+] Signature (base64):", base64.b64encode(signature).decode())

# Verify a message
def verify_message(message, signature_path):
    with open("ecc_sign_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    try:
        public_key.verify(
            signature,
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        print("[+] Signature is valid!")
    except Exception as e:
        print("[-] Invalid signature:", str(e))

def main():
    parser = argparse.ArgumentParser(description="ECC Digital Signature Tool")
    parser.add_argument('--generate-keys', action='store_true', help="Generate ECC key pair for signing")
    parser.add_argument('--sign', metavar='MESSAGE', help="Sign a message")
    parser.add_argument('--verify', nargs=2, metavar=('MESSAGE', 'SIGNATURE_FILE'), help="Verify a message with signature file")

    args = parser.parse_args()

    if args.generate_keys:
        generate_keys()
    elif args.sign:
        sign_message(args.sign)
    elif args.verify:
        verify_message(args.verify[0], args.verify[1])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
