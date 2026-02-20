from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256   # <-- use PyCryptodome's SHA256
import base64

# Derive AES key from passphrase using PBKDF2
def derive_key(passphrase, salt, iterations=200000):
    # dkLen=32 gives us a 256-bit key
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

# Encrypt data using AES-GCM with PBKDF2-derived key
def encrypt_data(passphrase, plaintext):
    salt = get_random_bytes(16)   # Random salt
    key = derive_key(passphrase.encode(), salt)
    nonce = get_random_bytes(12)  # 12-byte nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    # Store salt + nonce + tag + ciphertext together
    return base64.b64encode(salt + nonce + tag + ciphertext).decode()

# Decrypt data using AES-GCM with PBKDF2-derived key
def decrypt_data(passphrase, encoded):
    raw = base64.b64decode(encoded)
    salt = raw[:16]
    nonce = raw[16:28]
    tag = raw[28:44]
    ciphertext = raw[44:]
    key = derive_key(passphrase.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError:
        return "Tampering detected!"

# test
msg = input("Enter message: ")
passphrase = input("Enter password: ")
encoded = encrypt_data(passphrase, msg)
print("Encoded:", encoded)

decrypted = decrypt_data(passphrase, encoded)
print("Decrypted:", decrypted)

print("\n\n\n\nTest with wrong password...\n\n\n")
wrong_password = input("Another password: ")
try:
    decrypted = decrypt_data(wrong_password, encoded)
    print("Decrypted:", decrypted)
except Exception:
    print("Error happened")

