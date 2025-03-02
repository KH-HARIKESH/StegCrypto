import cv2
import numpy as np
from cryptography.fernet import Fernet
import hashlib
import base64
import sys
import os
import argparse
from typing import Tuple, Optional

class StegCrypto:
    def __init__(self):
        self.verification_delimiter = "||"
        
    # Generate encryption key (for AES-like encryption)
    def generate_key(self, save_path: Optional[str] = None) -> bytes:
        """Generate a secure encryption key and optionally save it to a file
        
        Args:
            save_path: Path to save the key (optional)
            
        Returns:
            The generated key as bytes
        """
        key = Fernet.generate_key()
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(key)
            print(f"Key saved to {save_path}")
        return key

    # Load key from file
    def load_key(self, key_path: str) -> bytes:
        """Load a key from a file
        
        Args:
            key_path: Path to the key file
            
        Returns:
            The loaded key as bytes
        """
        with open(key_path, 'rb') as f:
            return f.read()

    # Encrypt the message with integrity verification
    def encrypt_message(self, message: str, key: bytes) -> bytes:
        """Encrypt a message using the provided key
        
        Args:
            message: The message to encrypt
            key: The encryption key
            
        Returns:
            The encrypted message as bytes
        """
        # Add hash for integrity verification
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        message_with_hash = message + self.verification_delimiter + message_hash
        
        cipher = Fernet(key)
        encrypted_message = cipher.encrypt(message_with_hash.encode())
        return encrypted_message

    # Decrypt the message and verify integrity
    def decrypt_message(self, encrypted_message: bytes, key: bytes) -> Tuple[str, bool]:
        """Decrypt a message and verify its integrity
        
        Args:
            encrypted_message: The encrypted message
            key: The decryption key
            
        Returns:
            Tuple of (decrypted message, integrity verified)
        """
        try:
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_message).decode()
            
            # Split message and hash
            if self.verification_delimiter in decrypted_data:
                message, received_hash = decrypted_data.split(self.verification_delimiter)
                # Verify integrity
                calculated_hash = hashlib.sha256(message.encode()).hexdigest()
                integrity_verified = calculated_hash == received_hash
                return message, integrity_verified
            else:
                return decrypted_data, False
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    # Convert message to binary string
    def _message_to_binary(self, message: bytes) -> str:
        """Convert bytes to a binary string
        
        Args:
            message: Bytes to convert
            
        Returns:
            Binary string representation
        """
        return ''.join(format(byte, '08b') for byte in message)

    # Convert binary string back to bytes
    def _binary_to_bytes(self, binary_str: str) -> bytes:
        """Convert a binary string to bytes
        
        Args:
            binary_str: Binary string to convert
            
        Returns:
            Bytes representation
        """
        # Ensure binary string length is a multiple of 8
        padding = 8 - (len(binary_str) % 8) if len(binary_str) % 8 != 0 else 0
        binary_str = binary_str.ljust(len(binary_str) + padding, '0')
        
        # Convert groups of 8 bits to bytes
        bytes_data = bytearray()
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if byte:  # Ensure we have bits to convert
                bytes_data.append(int(byte, 2))
        
        return bytes(bytes_data)

    # Encode data in image using advanced LSB (configurable bit depth)
    def encode_image(self, img_path: str, message: str, output_path: str, key: bytes, bits_per_pixel: int = 1) -> None:
        """Hide encrypted data in image using LSB steganography
        
        Args:
            img_path: Path to the cover image
            message: Message to hide
            output_path: Path to save the encoded image
            key: Encryption key
            bits_per_pixel: Number of LSB bits to use per pixel (1-8)
        """
        # Validate bit depth
        if bits_per_pixel < 1 or bits_per_pixel > 4:
            raise ValueError("bits_per_pixel must be between 1 and 4")
            
        # Read image and check if it loaded successfully
        image = cv2.imread(img_path)
        if image is None:
            raise ValueError(f"Could not read image from {img_path}")
            
        # Encrypt message with integrity verification
        encrypted_message = self.encrypt_message(message, key)
        
        # Convert to binary and prepare for embedding
        binary_message = self._message_to_binary(encrypted_message)
        
        # Add length header (32 bits = 4 bytes for length)
        length_header = format(len(binary_message), '032b')
        binary_data = length_header + binary_message
        
        # Check if image is large enough for the message
        total_pixels = image.size // 3  # RGB channels
        max_bits = total_pixels * bits_per_pixel
        
        if len(binary_data) > max_bits:
            raise ValueError(f"Message too large for image with current settings. Maximum {max_bits//8} bytes, but need {len(binary_data)//8} bytes.")
        
        # Flatten image for easier processing
        img_data = image.reshape(-1)  # Flatten to 1D array
        
        # Embed data using specified bit depth
        data_index = 0
        bit_mask = (1 << bits_per_pixel) - 1  # Create mask for clearing bits
        
        for i in range(0, len(binary_data), bits_per_pixel):
            if data_index >= len(img_data):
                break
                
            # Get next chunk of bits to embed
            end_idx = min(i + bits_per_pixel, len(binary_data))
            bits_chunk = binary_data[i:end_idx]
            
            # Pad if needed
            if len(bits_chunk) < bits_per_pixel:
                bits_chunk = bits_chunk.ljust(bits_per_pixel, '0')
                
            # Convert bits to value
            bits_value = int(bits_chunk, 2)
            
            # Clear LSBs and set new value
            pixel_value = img_data[data_index]
            cleared_value = pixel_value & (255 - bit_mask)  # Alternative to using ~ operator
            img_data[data_index] = cleared_value | bits_value
            data_index += 1
        
        # Reshape back to original image dimensions
        encoded_image = img_data.reshape(image.shape)
        
        # Save encoded image
        cv2.imwrite(output_path, encoded_image)
        print(f"Message successfully hidden in {output_path}")

    # Decode hidden data from image
    def decode_image(self, img_path: str, key: bytes, bits_per_pixel: int = 1) -> str:
        """Extract and decrypt hidden message from image
        
        Args:
            img_path: Path to the encoded image
            key: Decryption key
            bits_per_pixel: Number of LSB bits used per pixel (1-8)
            
        Returns:
            The decrypted message
        """
        # Validate bit depth
        if bits_per_pixel < 1 or bits_per_pixel > 4:
            raise ValueError("bits_per_pixel must be between 1 and 4")
            
        # Read image
        image = cv2.imread(img_path)
        if image is None:
            raise ValueError(f"Could not read image from {img_path}")
            
        # Flatten image for easier processing
        img_data = image.reshape(-1)
        
        # Create mask for extracting bits
        bit_mask = (1 << bits_per_pixel) - 1
        
        # Extract length header first (32 bits)
        binary_length = ""
        for i in range(32 // bits_per_pixel):
            # Extract bits from pixel
            bits = img_data[i] & bit_mask
            # Convert to binary and pad
            binary_length += format(bits, f'0{bits_per_pixel}b')
        
        # Get message length (truncate to 32 bits if we read more)
        message_length = int(binary_length[:32], 2)
        
        # Calculate how many pixels we need to read for the full message
        total_pixels_needed = (message_length + bits_per_pixel - 1) // bits_per_pixel
        
        # Extract the binary message
        binary_message = ""
        for i in range(32 // bits_per_pixel, 32 // bits_per_pixel + total_pixels_needed):
            if i < len(img_data):
                # Extract bits from pixel
                bits = img_data[i] & bit_mask
                # Convert to binary and pad
                binary_message += format(bits, f'0{bits_per_pixel}b')
        
        # Truncate to the actual message length
        binary_message = binary_message[:message_length]
        
        # Convert binary to bytes
        encrypted_message = self._binary_to_bytes(binary_message)
        
        try:
            # Decrypt and verify integrity
            message, integrity_verified = self.decrypt_message(encrypted_message, key)
            
            if integrity_verified:
                return message
            else:
                raise ValueError("Message integrity verification failed! The data may have been tampered with.")
        except Exception as e:
            raise ValueError(f"Failed to decode message: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Advanced LSB Steganography with Cryptography')
    parser.add_argument('action', choices=['generate_key', 'encode', 'decode'], help='Action to perform')
    parser.add_argument('--image', help='Path to the input image')
    parser.add_argument('--output', help='Path to the output image (for encoding)')
    parser.add_argument('--message', help='Message to hide (for encoding)')
    parser.add_argument('--key', help='Path to the key file or the key itself')
    parser.add_argument('--save-key', help='Path to save the generated key')
    parser.add_argument('--bits', type=int, default=1, help='Number of LSB bits to use (1-4, default=1)')
    
    args = parser.parse_args()
    steg = StegCrypto()
    
    try:
        if args.action == 'generate_key':
            key = steg.generate_key(args.save_key)
            print(f"Generated Key: {key.decode()}")
            
        elif args.action == 'encode':
            if not all([args.image, args.output, args.message, args.key]):
                raise ValueError("Missing required arguments for encoding")
                
            # Determine if key is a file path or the key itself
            key = None
            if os.path.isfile(args.key):
                key = steg.load_key(args.key)
            else:
                try:
                    key = args.key.encode()
                    # Validate it's a valid Fernet key
                    Fernet(key)
                except Exception:
                    raise ValueError("Invalid key format. Please provide a valid key or key file path.")
            
            steg.encode_image(args.image, args.message, args.output, key, args.bits)
            
        elif args.action == 'decode':
            if not all([args.image, args.key]):
                raise ValueError("Missing required arguments for decoding")
                
            # Determine if key is a file path or the key itself
            key = None
            if os.path.isfile(args.key):
                key = steg.load_key(args.key)
            else:
                try:
                    key = args.key.encode()
                    # Validate it's a valid Fernet key
                    Fernet(key)
                except Exception:
                    raise ValueError("Invalid key format. Please provide a valid key or key file path.")
            
            message = steg.decode_image(args.image, key, args.bits)
            print(f"Decoded message: {message}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
