from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Function to encrypt a file using AES-GCM
def encrypt_file(input_file, output_file, key):
    nonce = get_random_bytes(12)  # 12-byte nonce for GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Read the entire file content (for simplicity in this lab)
    with open(input_file, 'rb') as f_in:
        plaintext = f_in.read()

    # Encrypt and generate authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Write nonce + tag + ciphertext to output file
    with open(output_file, 'wb') as f_out:
        f_out.write(nonce + tag + ciphertext)

# Function to decrypt a file using AES-GCM
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in:
        raw = f_in.read()

    # Extract nonce, tag, and ciphertext
    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_file, 'wb') as f_out:
            f_out.write(plaintext)
        print("File decrypted successfully")
    except ValueError:
        print("Tampering detected in file!")

# test
key = get_random_bytes(32)  # 256-bit key
# encrypt_file("secret.txt", "secret.enc", key)
decrypt_file("secret.enc", "secret_out.txt", key)
