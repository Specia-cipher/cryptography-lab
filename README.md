#SANNI-BABATUNDE-IDRIS
sannifreelancer6779@gmail.com
@Linkedin
https://www.linkedin.com/in/sanni-idris-89917a262?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app



# 🔐 Cryptography Lab


A collection of Python-based cryptographic tools for learning, experimentation, and practical application. This lab demonstrates various cryptographic primitives and concepts, including RSA, ECC, digital signatures, symmetric encryption, Diffie-Hellman key exchange, hybrid encryption, and password hashing.

_All tools authored by Sanni Idris (Specia-cipher)_

---

## 📑 Table of Contents
1. [RSA Tool](#rsa-tool)
2. [ECC Tool](#ecc-tool)
3. [Digital Signature Tools](#digital-signature-tools)
4. [Symmetric Encryption](#symmetric-encryption)
5. [Diffie-Hellman Key Exchange](#diffie-hellman-key-exchange)
6. [File Encryption Tool](#file-encryption-tool)
7. [Hybrid Encryption Tool](#hybrid-encryption-tool)
8. [Password Manager Tool](#password-manager-tool)

---

## 🛠 RSA Tool
Generate RSA key pairs, encrypt/decrypt files, and create digital signatures.

**Usage:**
```bash
# Generate RSA keys
python rsa_tool.py --generate-keys

# Encrypt a file
python rsa_tool.py --encrypt secret.txt --out secret.enc --pubkey rsa_public.pem

# Decrypt a file
python rsa_tool.py --decrypt secret.enc --out secret.txt --privkey rsa_private.pem

# Sign a file
python rsa_tool.py --sign secret.txt --privkey rsa_private.pem

# Verify a signature
python rsa_tool.py --verify secret.txt --pubkey rsa_public.pem --signature signature.sig

Author: Sanni Idris (Specia-cipher)


---

🪙 ECC Tool

Elliptic Curve Cryptography for key generation, encryption, and digital signatures.

Usage:

# Generate ECC keys
python ecc_tool.py --generate-keys

# Encrypt a file
python ecc_tool.py --encrypt message.txt --out message.enc --pubkey ecc_public.pem

# Decrypt a file
python ecc_tool.py --decrypt message.enc --out message.txt --privkey ecc_private.pem

# Sign a file
python ecc_tool.py --sign message.txt --privkey ecc_private.pem

# Verify a signature
python ecc_tool.py --verify message.txt --pubkey ecc_public.pem --signature signature.sig

Author: Sanni Idris (Specia-cipher)


---

✍ Digital Signature Tools

Standalone tools for creating and verifying RSA/ECC signatures.

Usage:

# Sign a file (RSA)
python rsa_sign_tool.py --sign file.txt --privkey rsa_sign_private_key.pem

# Verify signature (RSA)
python rsa_sign_tool.py --verify file.txt --pubkey rsa_sign_public_key.pem --signature file.sig

# Sign a file (ECC)
python ecc_sign_tool.py --sign file.txt --privkey ecc_sign_private_key.pem

# Verify signature (ECC)
python ecc_sign_tool.py --verify file.txt --pubkey ecc_sign_public_key.pem --signature file.sig

Author: Sanni Idris (Specia-cipher)


---

🔒 Symmetric Encryption

Encrypt and decrypt files using AES-256 in CBC mode.

Usage:

# Encrypt a file
python symmetric_encryption.py --encrypt plain.txt --out encrypted.bin --password "mypassword123"

# Decrypt a file
python symmetric_encryption.py --decrypt encrypted.bin --out decrypted.txt --password "mypassword123"

Author: Sanni Idris (Specia-cipher)


---

🔄 Diffie-Hellman Key Exchange

Tool for generating shared secrets over an insecure channel.

Usage:

# Generate DH parameters
python diffie_hell_tool.py --generate-params

# Generate keys for Alice
python diffie_hell_tool.py --generate-keys
mv dh_public_key.pem alice_public.pem
mv dh_private_key.pem alice_private.pem

# Generate keys for Bob
python diffie_hell_tool.py --generate-keys
mv dh_public_key.pem bob_public.pem
mv dh_private_key.pem bob_private.pem

# Compute shared secrets
mv alice_private.pem dh_private_key.pem
python diffie_hell_tool.py --compute-secret bob_public.pem
mv dh_shared_secret.bin alice_secret.bin

mv bob_private.pem dh_private_key.pem
python diffie_hell_tool.py --compute-secret alice_public.pem
mv dh_shared_secret.bin bob_secret.bin

# Verify secrets match
cmp alice_secret.bin bob_secret.bin && echo "[+] Secrets match!"

Author: Sanni Idris (Specia-cipher)


---

📂 File Encryption Tool

AES-CBC encryption and decryption for files using a password.

Usage:

# Encrypt a file
python file_encryption_tool.py --encrypt secret.txt --out secret.enc --password "mypassword123"

# Decrypt a file
python file_encryption_tool.py --decrypt secret.enc --out secret_decrypted.txt --password "mypassword123"

Author: Sanni Idris (Specia-cipher)


---

🌐 Hybrid Encryption Tool

Combines RSA (for key exchange) and AES (for file encryption).

Usage:

# Generate RSA keys
python hybrid_encryption_tool.py --generate-keys

# Encrypt a file
python hybrid_encryption_tool.py --encrypt message.txt --out message.enc --pubkey rsa_public.pem

# Decrypt a file
python hybrid_encryption_tool.py --decrypt message.enc --out decrypted.txt --privkey rsa_private.pem

Author: Sanni Idris (Specia-cipher)


---

🔑 Password Manager Tool

Hashes and verifies passwords using PBKDF2 and bcrypt. Interactive CLI.

Usage:

# Run tool
python password_manager_tool.py

# Select option:
# 1. Hash Password
# 2. Verify Password

Author: Sanni Idris (Specia-cipher)


## CONNECT WITH ME ON LINKEDIN 

https://www.linkedin.com/in/sanni-idris-89917a262?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app
