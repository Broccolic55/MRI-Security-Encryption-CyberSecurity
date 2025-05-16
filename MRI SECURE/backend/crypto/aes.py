"""
AES-128 Implementation for BrainSecureX
Provides encryption and decryption functions using AES in CBC mode
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
from functools import lru_cache


class AESCipher:
    """
    AES Cipher implementation with 128-bit key length
    Uses CBC mode with PKCS7 padding
    """
    
    def __init__(self, key=None):
        """
        Initialize with a key or generate a random one
        
        Args:
            key (bytes, optional): 16-byte key for AES-128. If None, a random key is generated.
        """
        if key is None:
            self.key = os.urandom(16)  # 128 bits = 16 bytes
        elif len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")
        else:
            self.key = key
            
    def get_key(self):
        """Return the current key in base64 encoding"""
        return base64.b64encode(self.key).decode('utf-8')
    
    def set_key(self, key_b64):
        """Set key from base64 encoded string"""
        key = base64.b64decode(key_b64)
        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")
        self.key = key
    
    # Cache base64 decode operations to avoid repeated work
    @staticmethod
    @lru_cache(maxsize=128)
    def _b64decode(data):
        return base64.b64decode(data)
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-128 in CBC mode
        
        Args:
            plaintext (str or bytes): Data to encrypt
            
        Returns:
            dict: Contains 'iv' and 'ciphertext' in base64 encoding
        """
        # Fast path for bytes
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8') if isinstance(plaintext, str) else str(plaintext).encode('utf-8')
            
        # Generate random IV
        iv = os.urandom(16)
        
        # Apply padding - optimize to avoid creating intermediate objects
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Create cipher and encrypt - reuse cipher object
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Avoid multiple encodings by encoding only once
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        
        return {
            'iv': iv_b64,
            'ciphertext': ciphertext_b64
        }
    
    def decrypt(self, encrypted_data):
        """
        Decrypt ciphertext using AES-128 in CBC mode
        
        Args:
            encrypted_data (dict): Contains 'iv' and 'ciphertext' in base64 encoding
            
        Returns:
            bytes: Decrypted plaintext
        """
        # Use cached b64decode for better performance
        iv = self._b64decode(encrypted_data['iv'])
        ciphertext = self._b64decode(encrypted_data['ciphertext'])
        
        # Create cipher and decrypt - direct operation
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad in one operation
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_file(self, input_file_path, output_file_path):
        """
        Encrypt a file using AES-128
        
        Args:
            input_file_path (str): Path to the file to encrypt
            output_file_path (str): Path to save the encrypted file
        """
        with open(input_file_path, 'rb') as file:
            plaintext = file.read()
        
        encrypted = self.encrypt(plaintext)
        
        # Save IV and ciphertext in format: [16 bytes IV][ciphertext]
        iv = base64.b64decode(encrypted['iv'])
        ciphertext = base64.b64decode(encrypted['ciphertext'])
        
        with open(output_file_path, 'wb') as file:
            file.write(iv)
            file.write(ciphertext)
    
    def decrypt_file(self, input_file_path, output_file_path):
        """
        Decrypt a file encrypted with AES-128
        
        Args:
            input_file_path (str): Path to the encrypted file
            output_file_path (str): Path to save the decrypted file
        """
        with open(input_file_path, 'rb') as file:
            # Read IV (first 16 bytes)
            iv = file.read(16)
            # Read the rest as ciphertext
            ciphertext = file.read()
        
        encrypted_data = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
        
        plaintext = self.decrypt(encrypted_data)
        
        with open(output_file_path, 'wb') as file:
            file.write(plaintext)


# Example usage
if __name__ == "__main__":
    # Create a cipher with a random key
    cipher = AESCipher()
    print(f"Generated key: {cipher.get_key()}")
    
    # Example text encryption
    message = "This is a secret message for BrainSecureX"
    encrypted = cipher.encrypt(message)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt the message
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode('utf-8')}")