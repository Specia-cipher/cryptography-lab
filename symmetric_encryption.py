from cryptography.fernet import Fernet

# Generate a key and save it to a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Encryption key generated and saved to secret.key")

# Load the key from the file
def load_key():
    return open("secret.key", "rb").read()

# Encrypt a message
def encrypt_message(message_text):
    key = load_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message_text.encode())
    print(f"Original message: {message_text}")
    print(f"Encrypted message: {encrypted_message.decode()}")
    return encrypted_message

# Decrypt a message
def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    print(f"Decrypted message: {decrypted_message}")
    return decrypted_message

if __name__ == "__main__":
    generate_key() # This creates 'secret.key' in the same directory

    my_message = "Hello, Mobile Cryptography Lab!"
    encrypted = encrypt_message(my_message)

    # To demonstrate decryption, we'll decrypt the just-encrypted message
    decrypt_message(encrypted)
