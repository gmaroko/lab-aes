import os
import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Derive AES key from passphrase stored in environment variable
def derive_key():
    # Retrieve passphrase from environment variable (fallback to default if not set)
    passphrase = os.environ.get("MEMBER_DATA_PASSPHRASE", "default_pass")
    # Generate a random salt (16 bytes) to ensure unique key derivation
    salt = get_random_bytes(16)
    # Derive a 256-bit key using PBKDF2 with SHA256 and 200,000 iterations
    key = PBKDF2(passphrase.encode(), salt, dkLen=32, count=200000, hmac_hash_module=SHA256)
    return key, salt

# Encrypt a member record (dictionary) using AES-GCM
def encrypt_member_record(record: dict) -> str:
    key, salt = derive_key()
    nonce = get_random_bytes(12)  # 12-byte nonce for GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Convert dictionary to JSON string and then to bytes
    plaintext = json.dumps(record).encode()
    # Encrypt and generate authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # Encode salt + nonce + tag + ciphertext in base64 for safe storage/transmission
    return base64.b64encode(salt + nonce + tag + ciphertext).decode()

# Decrypt a member record from base64 string back to dictionary
def decrypt_member_record(encoded: str) -> dict:
    raw = base64.b64decode(encoded)
    # Extract salt (first 16 bytes), nonce (next 12), tag (next 16), and ciphertext (remaining)
    salt = raw[:16]
    nonce = raw[16:28]
    tag = raw[28:44]
    ciphertext = raw[44:]
    # Re-derive the same key using the original passphrase and extracted salt
    passphrase = os.environ.get("MEMBER_DATA_PASSPHRASE", "default_pass")
    key = PBKDF2(passphrase.encode(), salt, dkLen=32, count=200000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Decrypt and verify authentication tag
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    # Convert JSON string back to dictionary
    return json.loads(plaintext.decode())

# test
if __name__ == "__main__":
    record = {"name": "Maroko Gideon", "id": "672305", "balance": 150000.00}

    encrypted = encrypt_member_record(record)
    print("Encrypted:", encrypted)

    decrypted = decrypt_member_record(encrypted)
    print("Decrypted:", decrypted)
