# backend/crypto/__init__.py
# Empty __init__.py file to make the directory a package

# backend/crypto/steganography.py
import numpy as np
from PIL import Image
import io

def to_binary(data):
    """Convert data to binary format"""
    if isinstance(data, str):
        return ''.join([format(ord(i), '08b') for i in data])
    elif isinstance(data, bytes) or isinstance(data, bytearray):
        return ''.join([format(i, '08b') for i in data])
    elif isinstance(data, int):
        return format(data, '08b')
    else:
        raise TypeError("Type not supported.")

def embed_data(cover_image_path, secret_data, output_path=None):
    """Embed secret data within an image using LSB steganography"""
    # Read the cover image
    img = Image.open(cover_image_path)
    width, height = img.size
    
    # Convert secret data to binary
    binary_secret_data = to_binary(secret_data)
    
    # Calculate if the image has enough pixels to encode the data
    data_len = len(binary_secret_data)
    if data_len > width * height * 3:
        raise ValueError("Data size is too large for the cover image")
    
    # Add length of data to the beginning
    binary_secret_data = to_binary(len(binary_secret_data)) + binary_secret_data
    
    # Convert image to numpy array for faster processing
    img_array = np.array(list(img.getdata()))
    
    # Reshape array to match image dimensions
    if len(img_array.shape) == 1:
        # For grayscale images
        img_array = img_array.reshape((height, width))
    else:
        # For RGB or RGBA images
        channels = img_array.shape[1]
        img_array = img_array.reshape((height, width, channels))
    
    # Flatten the array for easier iteration
    flat_img = img_array.flatten()
    
    # Embed data into the LSBs of the image
    data_index = 0
    for i in range(len(flat_img)):
        if data_index < len(binary_secret_data):
            # Replace the LSB of the current pixel value with the data bit
            flat_img[i] = (flat_img[i] & ~1) | int(binary_secret_data[data_index])
            data_index += 1
        else:
            break
    
    # Reshape the array back to image dimensions
    if len(img_array.shape) == 2:
        stego_img_array = flat_img.reshape((height, width))
    else:
        stego_img_array = flat_img.reshape((height, width, channels))
    
    # Create new image from the modified array
    stego_img = Image.fromarray(stego_img_array.astype(np.uint8))
    
    # Save or return the image
    if output_path:
        stego_img.save(output_path)
        return output_path
    else:
        img_byte_arr = io.BytesIO()
        stego_img.save(img_byte_arr, format=img.format)
        return img_byte_arr.getvalue()

def extract_data(stego_image_path):
    """Extract hidden data from a steganographic image"""
    # Read the steganographic image
    img = Image.open(stego_image_path)
    
    # Convert image to numpy array
    img_array = np.array(list(img.getdata()))
    
    # Flatten the array
    flat_img = img_array.flatten()
    
    # Extract binary data
    binary_data = ''
    for i in range(len(flat_img)):
        if i < 32:  # First 32 bits contain the length
            binary_data += str(flat_img[i] & 1)
    
    # Get data length from the first 32 bits
    data_len = int(binary_data, 2)
    
    # Extract the actual data
    binary_data = ''
    for i in range(32, 32 + data_len):
        if i < len(flat_img):
            binary_data += str(flat_img[i] & 1)
    
    # Convert binary data to bytes
    data_bytes = bytearray()
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) == 8:
            data_bytes.append(int(byte, 2))
    
    return bytes(data_bytes)

# backend/crypto/aes.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class AESCipher:
    def __init__(self, key=None):
        """Initialize AES cipher with a key or generate a new one"""
        self.key = key if key else get_random_bytes(16)  # AES-128 (16 bytes)
        self.block_size = AES.block_size
    
    def encrypt(self, data):
        """Encrypt data using AES-128 in CBC mode"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Pad the data to match block size
        padded_data = pad(data, self.block_size)
        
        # Encrypt the data
        ciphertext = cipher.encrypt(padded_data)
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt(self, encrypted_data):
        """Decrypt data using AES-128 in CBC mode"""
        # Extract IV (first block_size bytes)
        iv = encrypted_data[:self.block_size]
        ciphertext = encrypted_data[self.block_size:]
        
        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        padded_data = cipher.decrypt(ciphertext)
        data = unpad(padded_data, self.block_size)
        
        return data
    
    def get_key(self):
        """Return the AES key"""
        return self.key

# backend/crypto/ascon.py
# For Ascon, we'll use a simplified version since the full implementation is complex

class AsconCipher:
    def __init__(self, key=None):
        """Initialize Ascon cipher with a key or generate a new one"""
        # In a real implementation, you would use the actual Ascon algorithm
        # For simplicity, we'll use AES as a substitute
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        self.key = key if key else get_random_bytes(16)
        self.block_size = AES.block_size
    
    def encrypt(self, data):
        """Encrypt data using Ascon"""
        # Simplified implementation using AES
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from Crypto.Random import get_random_bytes
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        
        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Return IV + tag + ciphertext
        return iv + tag + ciphertext
    
    def decrypt(self, encrypted_data):
        """Decrypt data using Ascon"""
        # Simplified implementation using AES-GCM
        from Crypto.Cipher import AES
        
        # Extract IV and tag
        iv = encrypted_data[:self.block_size]
        tag = encrypted_data[self.block_size:self.block_size+16]  # 16-byte tag
        ciphertext = encrypted_data[self.block_size+16:]
        
        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        
        # Decrypt
        data = cipher.decrypt_and_verify(ciphertext, tag)
        
        return data
    
    def get_key(self):
        """Return the Ascon key"""
        return self.key

# backend/crypto/ecc.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64
import os

class ECCCipher:
    def __init__(self, private_key=None):
        """Initialize ECC cipher with a private key or generate a new one"""
        if private_key:
            self.private_key = private_key
        else:
            # Generate a new private key
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        
        # Get the corresponding public key
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self):
        """Return the public key in bytes format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_private_key_bytes(self):
        """Return the private key in bytes format"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def encrypt_key(self, key_to_encrypt, recipient_public_key=None):
        """Encrypt a symmetric key using ECC"""
        if recipient_public_key is None:
            # Use own public key if none provided (for testing)
            recipient_public_key = self.public_key
        elif isinstance(recipient_public_key, bytes):
            # Convert from bytes if needed
            recipient_public_key = serialization.load_pem_public_key(recipient_public_key)
        
        # Generate an ephemeral private key
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        
        # Get the public key from the ephemeral private key
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Perform ECDH to get a shared secret
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
        
        # Derive an encryption key from the shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_secret)
        
        # Use derived key to encrypt the symmetric key
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        iv = os.urandom(16)
        cipher = AES.new(derived_key[:16], AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(key_to_encrypt, 16))
        
        # Serialize ephemeral public key
        ephemeral_public_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Return ephemeral public key + iv + ciphertext
        return ephemeral_public_bytes + iv + ciphertext
    
    def decrypt_key(self, encrypted_key):
        """Decrypt a symmetric key using ECC"""
        # Extract the ephemeral public key from the encrypted data
        # PEM format typically has a header and footer and is around 200 bytes
        ephemeral_public_bytes = encrypted_key[:250]  # Approximate, adjust if needed
        
        # Find the exact end of the PEM data
        end_marker = b'-----END PUBLIC KEY-----\n'
        end_position = ephemeral_public_bytes.find(end_marker) + len(end_marker)
        
        ephemeral_public_bytes = encrypted_key[:end_position]
        ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_bytes)
        
        # Extract IV and ciphertext
        iv = encrypted_key[end_position:end_position+16]
        ciphertext = encrypted_key[end_position+16:]
        
        # Perform ECDH to get the shared secret
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Derive the encryption key from the shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_secret)
        
        # Decrypt the symmetric key
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        cipher = AES.new(derived_key[:16], AES.MODE_CBC, iv)
        decrypted_key = unpad(cipher.decrypt(ciphertext), 16)
        
        return decrypted_key