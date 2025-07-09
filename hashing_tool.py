import argparse
import hashlib
import base64
import os
import sys

def hash_data(data, algorithm='sha256'):
    try:
        hash_func = hashlib.new(algorithm)
    except ValueError:
        print(f"Error: Unsupported algorithm '{algorithm}'. Supported algorithms are:")
        for algo in sorted(hashlib.algorithms_available):
            print(f" - {algo}")
        sys.exit(1)
    hash_func.update(data)
    return hash_func.digest()

def main():
    parser = argparse.ArgumentParser(description="Hashing Tool - hash strings or files with multiple algorithms.")
    parser.add_argument('--list', action='store_true', help="List all supported hash algorithms")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-m', '--message', help="Message string to hash")
    group.add_argument('-f', '--file', help="File path to hash")

    parser.add_argument('-a', '--algorithm', default='sha256', help="Hash algorithm (default: sha256)")
    parser.add_argument('-s', '--salt', help="Optional salt string to prepend to data (for password hashing)")
    parser.add_argument('-o', '--output', choices=['hex', 'base64'], default='hex', help="Output format (default: hex)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")

    args = parser.parse_args()

    if args.list:
        print("Supported hash algorithms:")
        for algo in sorted(hashlib.algorithms_available):
            print(f" - {algo}")
        return

    if not (args.message or args.file):
        parser.error("one of the arguments -m/--message or -f/--file is required unless --list is used")

    if args.message:
        data = args.message.encode()
        source = "message"
    else:
        if not os.path.isfile(args.file):
            print(f"Error: File '{args.file}' does not exist.")
            sys.exit(1)
        with open(args.file, 'rb') as f:
            data = f.read()
        source = f"file '{args.file}'"

    if args.salt:
        if args.verbose:
            print(f"Applying salt: {args.salt}")
        data = args.salt.encode() + data

    digest = hash_data(data, args.algorithm)

    if args.output == 'hex':
        output = digest.hex()
    else:
        output = base64.b64encode(digest).decode()

    if args.verbose:
        print(f"Algorithm: {args.algorithm.upper()}")
        print(f"Source: {source}")
        print(f"Output format: {args.output}")
        print(f"Hash: {output}")
    else:
        print(output)

if __name__ == "__main__":
    main()
