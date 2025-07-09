# 🔒 Cryptography Lab

A hands-on Python lab for exploring cryptography and security concepts. Built for tinkering, learning, and demonstrating skills in practical cryptography.  

This lab runs seamlessly in Termux (Android) and Linux environments—making cryptographic experiments possible even from a mobile setup.  

---

## 🚀 Current Tools
- 🔐 Hashing Tool — Multi-algorithm hashing with CLI flexibility.
- 🗝 Symmetric Encryption Tool — Simple AES encryption and decryption.

## 📡 Roadmap
##- Asymmetric Encryption (RSA, ECC)
- Digital Signatures and Verification
- Key Exchange Protocols (Diffie-Hellman, etc.)
- File encryption/decryption utilities
- Password managers & key derivation functions (PBKDF2, bcrypt)

---

## 📂 Tools

### 🔐 Hashing Tool
A flexible CLI utility for hashing strings or files using multiple algorithms.

**Features**
- Supports SHA-1, SHA-256, SHA-3, BLAKE2, MD5, and more.
- Optional salting for password-like hashing.
- Output formats: HEX or Base64.
- Verbose mode for detailed outputs.
- Lists all supported algorithms.

**Usage**
```bash
# List available algorithms
python hashing_tool.py --list

# Hash a simple message (default: sha256)
python hashing_tool.py -m "Hello, world!"

# Hash a file with SHA-512 and base64 output
python hashing_tool.py -f testfile.txt -a sha512 -o base64 -v


---

🗝 Symmetric Encryption Tool

Encrypt and decrypt text securely using Fernet (AES under the hood).

Features

Generates and stores a secure encryption key (secret.key).

Encrypts plaintext messages into ciphertext.

Decrypts ciphertext back into plaintext.

Simple and beginner-friendly API.


Usage

# Generate a new encryption key
python symmetric_encryption.py

# Encrypt a message
python symmetric_encryption.py -e "This is secret"

# Decrypt a message
python symmetric_encryption.py -d <encrypted_message>

Author Sanni Babatunde Idris (Specia-cipher)
🔗 GitHub | LinkedIn


---


## Roadmap checklist 


## 🔐 RSA Tool

A command-line utility to generate RSA keys, encrypt messages, and decrypt ciphertexts.

### Features
- Generate 2048-bit RSA key pair (`private_key.pem`, `public_key.pem`)
- Encrypt messages and save to file (`encrypted.bin`) or view as base64
- Decrypt ciphertexts from files or directly from base64 strings
- Built-in error handling for missing keys and malformed inputs

### Usage

#### Generate RSA Keys
```bash
python rsa_tool.py --generate-keys

## Encrypt a Message

python rsa_tool.py --encrypt "Hello RSA from the mobile lab"

## Decrypt from File

python rsa_tool.py --decrypt-file encrypted.bin

##Decrypt from Base64 String

python rsa_tool.py --decrypt-string "paste_base64_ciphertext_here"


---

Example Run

[+] RSA keys generated and saved as private_key.pem and public_key.pem
[+] Message encrypted and saved to encrypted.bin
[+] Encrypted (base64): <base64 output>
[+] Decrypted message: Hello RSA from the mobile lab


---

📌 This tool was designed in Termux as part of the mobile Cryptography Lab project.


---

👤 Author: Sanni Babatunde Idris (Specia-cipher)
🔗 GitHub • LinkedIn • 📧 sannifreelancer@gmail.com


---

---

### 3️⃣ ECC Tool (`ecc_tool.py`)

Elliptic Curve Cryptography (ECC) utilities for key generation, digital signing, and signature verification.

#### 📦 Features
- Generate ECC private and public key pairs.
- Sign messages and save signatures to file (`signature.sig`) and base64 format (`signature.b64`).
- Verify signatures from file or base64 strings.

#### ⚡ Usage

```bash
# Generate ECC key pair
python ecc_tool.py --generate-keys

# Sign a message
python ecc_tool.py --sign "Hello ECC mobile lab!"

# Verify signature from saved file
python ecc_tool.py --verify-file "Hello ECC mobile lab!" signature.sig

# Verify signature from base64 string
python ecc_tool.py --verify-base64 "Hello ECC mobile lab!" "<your_base64_signature>"

---

📁 Files Generated

ecc_private_key.pem: ECC private key.

ecc_public_key.pem: ECC public key.

signature.sig: Binary signature file.

signature.b64: Base64-encoded signature.


✍️ Author

Sanni Babatunde Idris (Specia-cipher)
GitHub • LinkedIn

---

#Next stop here 
---

📝 Development Environment

Language: Python 3.x

Environment: Termux (Android), Kali Linux, WSL2

Version Control: Git & GitHub

Dependencies: cryptography, hashlib, argparse



---

🙋‍♂️ Contributions

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.


---

👨‍💻 Author

Sanni Babatunde Idris (Specia-cipher)
📧 sannifreelancer@gmail.com
🔗 GitHub | LinkedIn
https://github.com/sanni-idris

https://linkedin.com/in/sanni-idris-89917a262
---

Thank you for checking out my Cryptography Lab. More tools coming soon… 🚀

---
