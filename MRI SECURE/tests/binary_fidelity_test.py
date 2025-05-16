"""
Binary Fidelity Test Script

This script tests whether the encryption and decryption process preserves
the exact binary content of medical images.
"""

import os
import sys
import hashlib
import base64
import tempfile
import shutil
import argparse
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.crypto.mri_encryptor import MRIEncryptor
from PIL import Image

def verify_file_integrity(original_path, restored_path):
    """Verify byte-for-byte integrity between original and restored files"""
    with open(original_path, 'rb') as f1, open(restored_path, 'rb') as f2:
        original_data = f1.read()
        restored_data = f2.read()
        
    if len(original_data) != len(restored_data):
        return False, f"Size mismatch: {len(original_data)} vs {len(restored_data)} bytes"
    
    differences = []
    for i, (b1, b2) in enumerate(zip(original_data, restored_data)):
        if b1 != b2:
            differences.append(i)
            if len(differences) > 10:  # Limit to first 10 differences
                break
                
    if differences:
        return False, f"Differences at positions: {differences}"
    
    return True, "Files are identical"

def test_binary_fidelity(test_image_path, output_dir=None):
    """Test binary fidelity of encryption and decryption process"""
    print(f"Testing binary fidelity with: {test_image_path}")
    
    # Create or use output directory for test outputs
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        temp_dir = output_dir
        delete_temp = False
    else:
        temp_dir = tempfile.mkdtemp()
        delete_temp = True
        
    try:
        # Calculate hash of original file
        with open(test_image_path, 'rb') as f:
            original_data = f.read()
            original_hash = hashlib.md5(original_data).hexdigest()
        
        image_info = os.path.basename(test_image_path)
        file_extension = os.path.splitext(test_image_path)[1].lower()
        original_size = len(original_data)
        
        print(f"Original file: {image_info}")
        print(f"Format: {file_extension}")
        print(f"Size: {original_size} bytes")
        print(f"MD5 hash: {original_hash}")
        
        # Create MRIEncryptor instance
        encryptor = MRIEncryptor()
        
        # Step 1: Encrypt the image with binary preservation
        print("\nStep 1: Encrypting image with binary preservation...")
        encrypted_payload = encryptor.encrypt_mri_image(test_image_path, preserve_original=True)
        
        # Verify the payload contains required fields
        binary_perfect = encrypted_payload.get('binary_perfect', False)
        has_original_binary = 'original_binary' in encrypted_payload
        has_hash = 'original_hash' in encrypted_payload
        
        print(f"Binary perfect mode: {binary_perfect}")
        print(f"Has original binary data: {has_original_binary}")
        print(f"Has hash verification: {has_hash}")
        
        # Step 2: Save encrypted payload
        encrypted_path = os.path.join(temp_dir, f'encrypted_{os.path.basename(test_image_path)}.json')
        print(f"\nStep 2: Saving encrypted payload to {encrypted_path}")
        encryptor.save_encrypted_image(encrypted_payload, encrypted_path)
        
        # Step 3: Load encrypted payload (simulates loading from storage)
        print("\nStep 3: Loading encrypted payload from file...")
        loaded_payload = encryptor.load_encrypted_image(encrypted_path)
        
        # Step 4: Check if payload was preserved correctly during save/load
        print("\nStep 4: Verifying payload integrity after save/load...")
        if loaded_payload.get('original_hash') == encrypted_payload.get('original_hash'):
            print("✓ Hash preserved in payload")
        else:
            print("❌ Hash changed in payload")
            
        if 'original_binary' in loaded_payload:
            binary_size = len(base64.b64decode(loaded_payload['original_binary']))
            print(f"Size of stored binary: {binary_size} bytes")
            if binary_size == original_size:
                print("✓ Binary size matches original")
            else:
                print(f"❌ Binary size mismatch: original={original_size}, stored={binary_size}")
                
        # Step 5: Extract and save the original binary data
        print("\nStep 5: Restoring binary data...")
        original_binary = base64.b64decode(loaded_payload['original_binary'])
        restored_path = os.path.join(temp_dir, f'restored_{os.path.basename(test_image_path)}')
        
        with open(restored_path, 'wb') as f:
            f.write(original_binary)
        
        # Calculate hash of restored file
        with open(restored_path, 'rb') as f:
            restored_data = f.read()
            restored_hash = hashlib.md5(restored_data).hexdigest()
        
        restored_size = os.path.getsize(restored_path)
        
        print(f"Restored file: {os.path.basename(restored_path)}")
        print(f"Size: {restored_size} bytes")
        print(f"MD5 hash: {restored_hash}")
        
        # Step 6: Compare the files byte by byte
        print("\nStep 6: Verifying binary fidelity...")
        identical, message = verify_file_integrity(test_image_path, restored_path)
        
        if identical:
            print("✓ SUCCESS: Binary fidelity maintained! Files are identical.")
            
            # Additional verification: Try to open both files as images
            try:
                original_img = Image.open(test_image_path)
                restored_img = Image.open(restored_path)
                
                print("\nImage validation:")
                print(f"Original: {original_img.format} {original_img.mode} {original_img.size}")
                print(f"Restored: {restored_img.format} {restored_img.mode} {restored_img.size}")
                
                if original_img.format == restored_img.format and original_img.size == restored_img.size:
                    print("✓ Image properties match")
                else:
                    print("⚠️ Image properties differ")
            except Exception as e:
                print(f"Image validation error: {e}")
        else:
            print(f"❌ FAILED: Binary fidelity lost! {message}")
            
        return identical
        
    finally:
        if delete_temp:
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test binary fidelity of encryption and decryption')
    parser.add_argument('-i', '--image', help='Path to test image')
    parser.add_argument('-o', '--output', help='Output directory for test files')
    
    args = parser.parse_args()
    
    # If no image specified, look for sample images
    if args.image:
        test_image_path = args.image
    else:
        # Use a sample image if none provided
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        test_image_path = os.path.join(base_dir, 'cover_images', 'sample.jpg')
        
        # Check if the default exists, otherwise look for any image
        if not os.path.exists(test_image_path):
            print("Looking for sample images...")
            for directory in ['cover_images', 'uploads', 'samples']:
                search_dir = os.path.join(base_dir, directory)
                if os.path.exists(search_dir):
                    image_files = [f for f in os.listdir(search_dir) 
                                  if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'))]
                    if image_files:
                        test_image_path = os.path.join(search_dir, image_files[0])
                        print(f"Found sample image: {test_image_path}")
                        break
    
    if not os.path.exists(test_image_path):
        print(f"Error: Test image not found.")
        print("Please provide a valid image path using the --image argument.")
        sys.exit(1)
    
    # Run the test
    success = test_binary_fidelity(test_image_path, args.output)
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
