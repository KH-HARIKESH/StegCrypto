import cv2
import numpy as np
from cryptography.fernet import Fernet
import hashlib
import base64
import sys


image = cv2.imread('input.jpg')

if image is None:
    print("Image not loaded. Double-check the file name and path.")
else:
    print("Image loaded successfully!")


# Generate encryption key (for AES-like encryption)
def generate_key():
    return Fernet.generate_key()


# Encrypt the message
def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message


# Decrypt the message
def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message


# Hide data in image using LSB
def encode_image(img_path, message, output_path, key):
    image = cv2.imread(img_path)
    message_hash = hashlib.sha256(message.encode()).hexdigest()
    encrypted_message = encrypt_message(message + "||" + message_hash, key)
    
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
    
    data_len = len(binary_message)
    img_data = image.flatten()
    
    if data_len > len(img_data):
        print("Message too large for image.")
        return
    
    for i in range(data_len):
        img_data[i] = (img_data[i] & 0xFE) | int(binary_message[i])
    
    encoded_image = img_data.reshape(image.shape)
    cv2.imwrite(output_path, encoded_image)
    print(f"Message hidden in {output_path}")


# Extract hidden data from image
def decode_image(img_path, key):
    image = cv2.imread(img_path)
    img_data = image.flatten()
    
    binary_message = ''
    for i in range(len(img_data)):
        binary_message += str(img_data[i] & 1)
    
    byte_data = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    encrypted_message = bytes([int(byte, 2) for byte in byte_data])
    
    try:
        decrypted_message = decrypt_message(encrypted_message, key)
        message, msg_hash = decrypted_message.split("||")
        
        # Verify integrity
        if hashlib.sha256(message.encode()).hexdigest() == msg_hash:
            print("Decrypted message:", message)
        else:
            print("Message integrity compromised!")
    except Exception as e:
        print("Failed to decrypt message:", e)


# CLI for testing
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Not enough arguments provided.")
        print("Usage for generating key: python steganography.py generate_key")
        print("Usage for encoding: python steganography.py encode input.png output.png 'Your message' YOUR_KEY")
        print("Usage for decoding: python steganography.py decode encoded_image.png YOUR_KEY")
        sys.exit(1)
    
    action = sys.argv[1]
    
    if action == "generate_key":
        key = generate_key()
        print("Generated Key:", key.decode())
    
    elif action == "encode":
        if len(sys.argv) < 6:
            print("Error: Not enough arguments for encoding.")
            print("Usage: python steganography.py encode input.png output.png 'Your message' YOUR_KEY")
            sys.exit(1)
        img_path = sys.argv[2]
        output_path = sys.argv[3]
        message = sys.argv[4]
        key = sys.argv[5].encode()
        encode_image(img_path, message, output_path, key)
    
    elif action == "decode":
        if len(sys.argv) < 4:
            print("Error: Not enough arguments for decoding.")
            print("Usage: python steganography.py decode encoded_image.png YOUR_KEY")
            sys.exit(1)
        img_path = sys.argv[2]
        key = sys.argv[3].encode()
        decode_image(img_path, key)
    
    else:
        print("Invalid action! Use 'generate_key', 'encode', or 'decode'.")

# To run:
# Generate a key: python script.py generate_key
# Encode: python script.py encode input.png output.png "Secret Message" <KEY>
# Decode: python script.py decode output.png <KEY>

# Let me know if you want me to refine this or help with the GitHub README and PPT! 🚀
