"""
Steganography Implementation for BrainSecureX
Provides functionality to hide and extract data within image files.

Supports:
- LSB (Least Significant Bit) steganography in PNG images
- Integration with encryption modules for secure data hiding
"""

import os
import base64
import json
import random
from PIL import Image
import numpy as np

class Steganography:
    """
    Implementation of steganography techniques for hiding data in images
    """
    
    def __init__(self):
        """Initialize the steganography module"""
        self.supported_formats = ['PNG']
        
    def _check_image_compatibility(self, image_path):
        """
        Check if the image is compatible for steganography
        
        Args:
            image_path (str): Path to the image file
            
        Returns:
            bool: True if compatible, False otherwise
        """
        try:
            img = Image.open(image_path)
            format_ok = img.format in self.supported_formats
            img.close()
            return format_ok
        except Exception as e:
            print(f"Error checking image compatibility: {e}")
            return False
    
    def _get_image_capacity(self, image_path):
        """
        Calculate the maximum bytes that can be hidden in an image
        
        Args:
            image_path (str): Path to the image file
            
        Returns:
            int: Maximum bytes capacity
        """
        img = Image.open(image_path)
        width, height = img.size
        channels = len(img.getbands())
        
        # Each pixel can store 1 bit per channel in LSB mode
        # Divide by 8 to convert bits to bytes
        capacity = (width * height * channels) // 8
        
        # Reserve some bytes for metadata (length of hidden data)
        return capacity - 16
    
    def _int_to_bin(self, integer, width=8):
        """Convert an integer to binary string with fixed width"""
        return bin(integer)[2:].zfill(width)
    
    def _bin_to_int(self, binary):
        """Convert a binary string to integer"""
        return int(binary, 2)
    
    def _str_to_bin(self, text):
        """Convert string to binary"""
        if isinstance(text, str):
            text = text.encode('utf-8')
        return ''.join(self._int_to_bin(byte) for byte in text)
    
    def _bin_to_str(self, binary):
        """Convert binary to string"""
        # Ensure binary string length is a multiple of 8
        binary = binary.zfill((len(binary) + 7) // 8 * 8)
        
        bytes_array = bytearray()
        for i in range(0, len(binary), 8):
            byte = self._bin_to_int(binary[i:i+8])
            bytes_array.append(byte)
            
        return bytes(bytes_array)
    
    def hide_data_lsb(self, image_path, data, output_path=None, password=None):
        """
        Hide data in an image using the LSB (Least Significant Bit) technique
        
        Args:
            image_path (str): Path to the carrier image
            data (str or bytes): Data to hide
            output_path (str, optional): Path to save the output image. If None, uses original path.
            password (str, optional): Password to use as seed for bit distribution
            
        Returns:
            str: Path to the output image
        """
        if not self._check_image_compatibility(image_path):
            raise ValueError(f"Image format not supported. Use {', '.join(self.supported_formats)}")
        
        # Convert data to bytes if it's a string
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Calculate capacity and check if data fits
        capacity = self._get_image_capacity(image_path)
        if len(data) > capacity:
            raise ValueError(f"Data too large. Max capacity: {capacity} bytes, Data size: {len(data)} bytes")
        
        # Open the image
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Get image dimensions
        height, width, channels = img_array.shape
        
        # Create binary representation of data length (32 bits = 4 bytes)
        length_bin = self._int_to_bin(len(data), 32)
        
        # Create binary representation of data
        data_bin = ''.join(self._int_to_bin(byte) for byte in data)
        
        # Combine length and data
        binary_data = length_bin + data_bin
        binary_length = len(binary_data)
        
        # Seed random number generator if password is provided
        if password:
            seed = sum(ord(char) for char in password)
            random.seed(seed)
            
            # Create a random distribution of pixel positions
            pixels = [(y, x) for y in range(height) for x in range(width)]
            random.shuffle(pixels)
        
        # Embed data in the image
        bit_index = 0
        
        # Modify image array based on binary data
        if password:
            # Using randomized pixel positions
            for pixel_index in range(binary_length):
                if bit_index >= binary_length:
                    break
                    
                y, x = pixels[pixel_index]
                channel = pixel_index % channels
                
                # Get the current pixel value
                pixel_value = img_array[y, x, channel]
                
                # Clear the least significant bit
                pixel_value = pixel_value & 0xFE
                
                # Set the least significant bit based on our data
                pixel_value = pixel_value | int(binary_data[bit_index])
                
                # Update the pixel
                img_array[y, x, channel] = pixel_value
                
                bit_index += 1
        else:
            # Sequential embedding
            for y in range(height):
                if bit_index >= binary_length:
                    break
                    
                for x in range(width):
                    if bit_index >= binary_length:
                        break
                        
                    for c in range(channels):
                        if bit_index >= binary_length:
                            break
                            
                        # Get the current pixel value
                        pixel_value = img_array[y, x, c]
                        
                        # Clear the least significant bit
                        pixel_value = pixel_value & 0xFE
                        
                        # Set the least significant bit based on our data
                        pixel_value = pixel_value | int(binary_data[bit_index])
                        
                        # Update the pixel
                        img_array[y, x, c] = pixel_value
                        
                        bit_index += 1
        
        # Create a new image from the modified array
        output_img = Image.fromarray(img_array)
        
        # Save the output image
        if output_path is None:
            file_name, ext = os.path.splitext(image_path)
            output_path = f"{file_name}_stego.png"
            
        output_img.save(output_path, "PNG")
        
        return output_path
    
    def extract_data_lsb(self, image_path, password=None):
        """
        Extract hidden data from an image using the LSB technique
        
        Args:
            image_path (str): Path to the image containing hidden data
            password (str, optional): Password used during hiding
            
        Returns:
            bytes: Extracted data
        """
        if not self._check_image_compatibility(image_path):
            raise ValueError(f"Image format not supported. Use {', '.join(self.supported_formats)}")
        
        # Open the image
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Get image dimensions
        height, width, channels = img_array.shape
        
        # Seed random number generator if password is provided
        if password:
            seed = sum(ord(char) for char in password)
            random.seed(seed)
            
            # Create a random distribution of pixel positions (same as in hide_data_lsb)
            pixels = [(y, x) for y in range(height) for x in range(width)]
            random.shuffle(pixels)
        
        # Extract bits from the image
        binary_data = ""
        
        # First, extract length (32 bits)
        if password:
            # Using randomized pixel positions
            for pixel_index in range(32):
                y, x = pixels[pixel_index]
                channel = pixel_index % channels
                
                # Get the LSB of the pixel
                binary_data += str(img_array[y, x, channel] & 1)
        else:
            # Sequential extraction
            for y in range(height):
                if len(binary_data) >= 32:
                    break
                    
                for x in range(width):
                    if len(binary_data) >= 32:
                        break
                        
                    for c in range(channels):
                        if len(binary_data) >= 32:
                            break
                            
                        # Get the LSB of the pixel
                        binary_data += str(img_array[y, x, c] & 1)
        
        # Convert the first 32 bits to get the data length
        data_length = self._bin_to_int(binary_data[:32])
        data_length_bits = data_length * 8
        
        # Clear binary data and extract actual data
        binary_data = ""
        
        if password:
            # Using randomized pixel positions
            for pixel_index in range(32, 32 + data_length_bits):
                if pixel_index >= len(pixels):
                    break
                    
                y, x = pixels[pixel_index]
                channel = pixel_index % channels
                
                # Get the LSB of the pixel
                binary_data += str(img_array[y, x, channel] & 1)
        else:
            # Reset counters for sequential extraction
            bit_count = 0
            for y in range(height):
                if bit_count >= data_length_bits:
                    break
                    
                for x in range(width):
                    if bit_count >= data_length_bits:
                        break
                        
                    for c in range(channels):
                        bit_count += 1
                        
                        if bit_count <= 32:
                            continue  # Skip the length bits
                            
                        if bit_count > 32 + data_length_bits:
                            break
                            
                        # Get the LSB of the pixel
                        binary_data += str(img_array[y, x, c] & 1)
        
        # Convert binary to bytes
        data = self._bin_to_str(binary_data[:data_length_bits])
        
        return data
    
    def hide_data_with_encryption(self, image_path, data, encryption_module, output_path=None, password=None):
        """
        Hide encrypted data in an image
        
        Args:
            image_path (str): Path to the carrier image
            data (str or bytes): Data to hide
            encryption_module: Instance of encryption class (AES, ASCON, or ECC)
            output_path (str, optional): Path to save the output image
            password (str, optional): Password for steganography bit distribution
            
        Returns:
            str: Path to the output image
        """
        # Encrypt the data
        if hasattr(encryption_module, 'encrypt'):
            encrypted_data = encryption_module.encrypt(data)
            # Convert to JSON string
            encrypted_json = json.dumps(encrypted_data).encode('utf-8')
            
            # Hide the encrypted data
            return self.hide_data_lsb(image_path, encrypted_json, output_path, password)
        else:
            raise ValueError("Encryption module does not have an encrypt method")
    
    def extract_data_with_decryption(self, image_path, decryption_module, password=None):
        """
        Extract and decrypt hidden data from an image
        
        Args:
            image_path (str): Path to the image containing hidden data
            decryption_module: Instance of encryption class (AES, ASCON, or ECC)
            password (str, optional): Password used during hiding
            
        Returns:
            bytes: Decrypted data
        """
        # Extract the hidden data
        encrypted_json = self.extract_data_lsb(image_path, password)
        
        # Parse the JSON
        encrypted_data = json.loads(encrypted_json)
        
        # Decrypt the data
        if hasattr(decryption_module, 'decrypt'):
            return decryption_module.decrypt(encrypted_data)
        else:
            raise ValueError("Decryption module does not have a decrypt method")


# Example usage
if __name__ == "__main__":
    # Create steganography instance
    stego = Steganography()
    
    # Example: Hide text in an image
    input_image = r"D:\Mini\dataset\brain img.png"
    output_image = r"D:\Mini\dataset\7482912e504dfafba69a0ff358c674a7.png"
    
    secret_message = "This is a hidden message for BrainSecureX"
    
    try:
        # Check if the image has enough capacity
        capacity = stego._get_image_capacity(input_image)
        print(f"Image capacity: {capacity} bytes")
        print(f"Message size: {len(secret_message)} bytes")
        
        if len(secret_message) <= capacity:
            # Hide the message
            result_path = stego.hide_data_lsb(input_image, secret_message, output_image)
            print(f"Data hidden successfully in: {result_path}")
            
            # Extract the message
            extracted_data = stego.extract_data_lsb(result_path)
            print(f"Extracted message: {extracted_data.decode('utf-8')}")
        else:
            print("Message too large for this image")
    
    except Exception as e:
        print(f"Error: {e}")