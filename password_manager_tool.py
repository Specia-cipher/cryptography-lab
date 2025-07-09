#!/usr/bin/env python3
import hashlib
import os
import base64
import bcrypt

def hash_pbkdf2(password, iterations=100000):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode()
    key_b64 = base64.b64encode(key).decode()
    return f"pbkdf2${iterations}${salt_b64}${key_b64}"

def verify_pbkdf2(password, stored_hash):
    try:
        _, iterations, salt_b64, key_b64 = stored_hash.split("$")
        salt = base64.b64decode(salt_b64)
        stored_key = base64.b64decode(key_b64)
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, int(iterations))
        return new_key == stored_key
    except Exception as e:
        print(f"[-] Error parsing PBKDF2 hash: {e}")
        return False

def hash_bcrypt(password, cost=12):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost))
    return f"bcrypt${hashed.decode()}"

def verify_bcrypt(password, stored_hash):
    try:
        _, bcrypted = stored_hash.split("$", 1)
        return bcrypt.checkpw(password.encode(), bcrypted.encode())
    except Exception as e:
        print(f"[-] Error parsing bcrypt hash: {e}")
        return False

def main():
    print("Password Manager Tool")
    print("---------------------")
    print("1. Hash Password")
    print("2. Verify Password")
    choice = input("Select option (1/2): ")

    if choice == "1":
        password = input("Enter password to hash: ")
        method = input("Choose method (pbkdf2/bcrypt): ").lower()
        if method == "pbkdf2":
            hash_out = hash_pbkdf2(password)
        elif method == "bcrypt":
            hash_out = hash_bcrypt(password)
        else:
            print("[-] Invalid method")
            return
        print(f"[+] Hashed password: {hash_out}")

    elif choice == "2":
        password = input("Enter password to verify: ")
        stored_hash = input("Enter stored hash: ")
        if stored_hash.startswith("pbkdf2$"):
            result = verify_pbkdf2(password, stored_hash)
        elif stored_hash.startswith("bcrypt$"):
            result = verify_bcrypt(password, stored_hash)
        else:
            print("[-] Unknown hash format")
            return
        if result:
            print("[+] Password is valid!")
        else:
            print("[-] Invalid password.")
    else:
        print("[-] Invalid option")

if __name__ == "__main__":
    main()
