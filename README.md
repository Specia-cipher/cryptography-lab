# 🔒 Cryptography Lab

A hands-on Python lab for exploring cryptography and security concepts. Built for tinkering, learning, and demonstrating skills in practical cryptography.  

This lab runs seamlessly in Termux (Android) and Linux environments—making cryptographic experiments possible even from a mobile setup.  

---

## 🚀 Current Tools
- 🔐 Hashing Tool — Multi-algorithm hashing with CLI flexibility.
- 🗝 Symmetric Encryption Tool — Simple AES encryption and decryption.

## 📡 Roadmap
- Asymmetric Encryption (RSA, ECC)
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


Perfect. That’s the professional developer way—every tool feels like a mini-project with its own little “signature block” at the end.

Here’s your redesigned, future-proof README.md:


---

# 🔒 Cryptography Lab

A hands-on Python lab for exploring cryptography and security concepts. Built for tinkering, learning, and demonstrating skills in practical cryptography.  

This lab runs seamlessly in Termux (Android) and Linux environments—making cryptographic experiments possible even from a mobile setup.  

---

## 🚀 Current Tools
- 🔐 Hashing Tool — Multi-algorithm hashing with CLI flexibility.
- 🗝 Symmetric Encryption Tool — Simple AES encryption and decryption.

## 📡 Roadmap
- Asymmetric Encryption (RSA, ECC)
- Digital Signatures and Verification
- Key Exchange Protocols (Diffie-Hellman, etc.)
- Steganography Utilities (Hide data in images, audio)
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

Author Sanni Babatunde Idris (Specia-cipher)
🔗 GitHub | LinkedIn


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

📦 Additions

(Future tools will appear here in this format)


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
