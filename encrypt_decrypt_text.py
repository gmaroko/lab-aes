from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

BLOCK_SIZE = 16

# Function to apply PKCS7 padding so plaintext fits into 16-byte blocks
def pkcs7_pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

# Function to remove PKCS7 padding after decryption
def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Generate a random 256-bit AES key (32 bytes)
key = get_random_bytes(32)

# Generate a random 16-byte IV for CBC mode
iv = get_random_bytes(16)

# get message from user input
plaintext = input("Enter message to encrypt: ")
plaintext = str(plaintext).encode("UTF-8")

# Encrypt using AES in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pkcs7_pad(plaintext))

# Encode IV + ciphertext in base64 for safe storage/transmission
encoded = base64.b64encode(iv + ciphertext).decode()
print('Encoded message:', encoded)


# Decrypt
# Decode base64 back to raw bytes
raw = base64.b64decode(encoded)

# Extract IV (first 16 bytes) and ciphertext (remaining bytes)
iv2 = raw[:16]
ciphertext2 = raw[16:]

# Decrypt using the same key and extracted IV
cipher2 = AES.new(key, AES.MODE_CBC, iv2)
pt = pkcs7_unpad(cipher2.decrypt(ciphertext2))

print('Plaintext msg:', pt) # Print final decoded plaintext