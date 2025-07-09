import hashlib
import argparse

def hash_message(message, algorithm='sha256'):
    try:
        hash_func = hashlib.new(algorithm)
    except ValueError:
        print(f"Error: Unsupported hash algorithm '{algorithm}'. Using SHA-256 instead.")
        hash_func = hashlib.sha256()
    hash_func.update(message.encode())
    return hash_func.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Hashing Tool - Generate hash digests of input messages.")
    parser.add_argument('message', help='The message to hash')
    parser.add_argument('-a', '--algorithm', default='sha256', help='Hash algorithm (default: sha256)')
    args = parser.parse_args()

    digest = hash_message(args.message, args.algorithm)
    print(f"Algorithm: {args.algorithm.upper()}")
    print(f"Message: {args.message}")
    print(f"Hash: {digest}")

if __name__ == "__main__":
    main()
