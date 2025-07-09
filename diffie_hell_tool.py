import argparse
import json
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Generate DH parameters (p, g)
def generate_params():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    params_numbers = parameters.parameter_numbers()
    params = {
        "p": params_numbers.p,
        "g": params_numbers.g
    }
    with open("dh_params.json", "w") as f:
        json.dump(params, f)
    print("[+] DH parameters generated and saved to dh_params.json")

# --- Generate private/public key pair
def generate_keys():
    if not os.path.exists("dh_params.json"):
        print("[-] DH parameters not found. Generate them first with --generate-params")
        return
    with open("dh_params.json", "r") as f:
        params_data = json.load(f)
    pn = dh.DHParameterNumbers(params_data["p"], params_data["g"])
    parameters = pn.parameters(default_backend())

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    # Save private key
    with open("dh_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save public key
    with open("dh_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("[+] DH private and public keys saved to dh_private_key.pem and dh_public_key.pem")

# --- Compute shared secret
def compute_secret(peer_public_key_file, verbose=False):
    if not os.path.exists("dh_private_key.pem"):
        print("[-] Private key not found. Generate keys first with --generate-keys")
        return
    if not os.path.exists(peer_public_key_file):
        print(f"[-] Peer public key file '{peer_public_key_file}' not found.")
        return

    # Load private key
    with open("dh_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    # Load peer public key
    with open(peer_public_key_file, "rb") as f:
        peer_public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )

    # Compute shared secret
    shared_key = private_key.exchange(peer_public_key)
    if verbose:
        print(f"[DEBUG] Shared secret (raw bytes): {shared_key.hex()}")
    print("[+] Shared secret computed successfully.")

    # Save shared secret
    with open("dh_shared_secret.bin", "wb") as f:
        f.write(shared_key)
    print("[+] Shared secret saved to dh_shared_secret.bin")

# --- Main CLI
def main():
    parser = argparse.ArgumentParser(description="Diffie-Hellman Key Exchange Tool")
    parser.add_argument("--generate-params", action="store_true", help="Generate DH parameters (p, g)")
    parser.add_argument("--generate-keys", action="store_true", help="Generate private/public key pair")
    parser.add_argument("--compute-secret", metavar="PEER_PUB_KEY", help="Compute shared secret using peer's public key")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.generate_params:
        generate_params()
    elif args.generate_keys:
        generate_keys()
    elif args.compute_secret:
        compute_secret(args.compute_secret, args.verbose)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
