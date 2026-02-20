from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate a random 256-bit AES key (32 bytes)
key = get_random_bytes(32)

# Generate a random 12-byte nonce (recommended size for GCM)
nonce = get_random_bytes(12)

# get message from user input
plaintext = input("Enter message to encrypt: ")
plaintext = str(plaintext).encode("UTF-8")

# Encrypt using AES in GCM mode
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

# Encrypt plaintext and generate authentication tag
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Encode nonce + tag + ciphertext in base64 for safe storage/transmission
encoded = base64.b64encode(nonce + tag + ciphertext).decode()
print("Encoded:", encoded)


# Decrypt
# Decode base64 back to raw bytes
raw = base64.b64decode(encoded)

# Extract nonce (first 12 bytes), tag (next 16 bytes), and ciphertext (remaining bytes)
nonce2 = raw[:12]
tag2 = raw[12:28]
ciphertext2 = raw[28:]
ciphertext3 = ciphertext2

# Decrypt using the same key and extracted nonce
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce2)

try:
    # Verify authentication tag during decryption
    pt = cipher2.decrypt_and_verify(ciphertext2, tag2)
    print('Verified plaintext:', pt)
except ValueError:
    # Raised if ciphertext or tag has been tampered with
    print('Tampering detected!')


# Tampering test
print("\n\n\nTamper test...\n\n")
# Convert ciphertext to mutable bytearray 
tampered_ciphertext = bytearray(ciphertext2)

# Flip one bit in the ciphertext to simulate tampering 
tampered_ciphertext[0] ^= 1 

# Attempt decryption with tampered data 
cipher3 = AES.new(key, AES.MODE_GCM, nonce=nonce2)
try:
    pt = cipher3.decrypt_and_verify(bytes(tampered_ciphertext), tag2)
    print('Verified plaintext (tampered):', pt)
except ValueError:
    print('Tampering detected on modified ciphertext!')
