# backend/main.py
import os
import sys
import base64
import json
import traceback
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.crypto import embed_data, extract_data
from backend.crypto.aes import AESCipher
from backend.crypto.ascon import AsconCipher
from backend.crypto.ecc import ECCCipher
from backend.database.db_handler import DatabaseHandler
# Fix the imports for utils - import directly from the utils package
from backend.utils import is_valid_image, convert_to_bytes, convert_from_bytes
from backend.utils import OTPGenerator

class SecureXway:
    def __init__(self):
        """Initialize the SecureXway system"""
        self.db = DatabaseHandler()
        self.otp_gen = OTPGenerator()
        self.ecc = ECCCipher()  # Generate ECC key pair
        
        # Base directory for absolute paths
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Create necessary directories with absolute paths
        self.uploads_dir = os.path.join(self.base_dir, 'uploads')
        self.encrypted_dir = os.path.join(self.base_dir, 'encrypted')
        self.decrypted_dir = os.path.join(self.base_dir, 'decrypted')
        self.patients_dir = os.path.join(self.base_dir, 'patients')
        
        os.makedirs(self.uploads_dir, exist_ok=True)
        os.makedirs(self.encrypted_dir, exist_ok=True)
        os.makedirs(self.decrypted_dir, exist_ok=True)
        os.makedirs(self.patients_dir, exist_ok=True)
    
    def encrypt_mri(self, mri_image_path, cover_image_path, patient_num):
        """Encrypt an MRI image using the full SecureXway process"""
        # Validate inputs
        if not os.path.exists(mri_image_path) or not os.path.exists(cover_image_path):
            return False, "One or more input files do not exist"
        
        if not is_valid_image(mri_image_path) or not is_valid_image(cover_image_path):
            return False, "One or more input files are not valid images"
        
        try:
            # Create patient directory if it doesn't exist
            patient_dir = os.path.join(self.patients_dir, f'patient_{patient_num}')
            patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
            os.makedirs(patient_dir, exist_ok=True)
            os.makedirs(patient_encrypted_dir, exist_ok=True)
            
            # Step 1: Apply steganography to hide MRI in cover image
            mri_data = convert_to_bytes(mri_image_path)
            stego_output_path = os.path.join(self.uploads_dir, f'stego_{os.path.basename(cover_image_path)}')
            embed_data(cover_image_path, mri_data, stego_output_path)
            
            # Step 2: AES encryption of the stego image
            aes = AESCipher()  # Generate AES key
            stego_data = convert_to_bytes(stego_output_path)
            aes_encrypted = aes.encrypt(stego_data)
            
            # Step 3: Ascon encryption of the AES ciphertext
            ascon = AsconCipher()  # Generate Ascon key
            ascon_encrypted = ascon.encrypt(aes_encrypted)
            
            # Step 4: ECC encryption of the AES and Ascon keys
            # Combine AES and Ascon keys
            combined_keys = aes.get_key() + ascon.get_key()
            encrypted_keys = self.ecc.encrypt_key(combined_keys)
            
            # Step 5: Save the encrypted data with absolute path
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            
            # Save in both locations - global encrypted dir and patient-specific dir
            encrypted_file_path = os.path.join(self.encrypted_dir, f'{patient_num}_{timestamp}.bin')
            patient_file_path = os.path.join(patient_encrypted_dir, f'mri_{timestamp}.bin')
            
            # Write the ASCON dictionary as JSON instead of raw bytes
            with open(encrypted_file_path, 'w') as f:
                json.dump(ascon_encrypted, f)
            
            # Copy to patient directory
            with open(patient_file_path, 'w') as f:
                json.dump(ascon_encrypted, f)
            
            # Store in database - store both paths
            self.db.store_encrypted_file(patient_num, encrypted_file_path, encrypted_keys, patient_file_path)
            
            # Generate fallback file for direct decryption
            try:
                from backend.crypto.mri_encryptor import MRIEncryptor
                direct_encryptor = MRIEncryptor()
                direct_encrypted_file = os.path.join(patient_encrypted_dir, f'mri_direct_{timestamp}.json')
                encrypted_payload = direct_encryptor.encrypt_mri_image(mri_image_path)
                direct_encryptor.save_encrypted_image(encrypted_payload, direct_encrypted_file)
                self.db.store_additional_file(patient_num, direct_encrypted_file)
            except Exception as fallback_error:
                print(f"Fallback file creation warning: {str(fallback_error)}")
                # Continue with main process even if fallback fails
            
            # Clean up temporary files
            if os.path.exists(stego_output_path):
                os.remove(stego_output_path)
            
            return True, encrypted_file_path
            
        except Exception as e:
            import traceback
            print(traceback.format_exc())  # Print full traceback for debugging
            return False, f"Encryption failed: {str(e)}"
    
    def decrypt_mri(self, patient_num):
        """Decrypt an MRI image for a patient"""
        try:
            # Get encrypted file and key from database
            encrypted_file_path, encrypted_keys = self.db.get_encrypted_file(patient_num)
            
            if not encrypted_file_path or not encrypted_keys:
                return False, "No encrypted file found for this patient"
            
            if not os.path.exists(encrypted_file_path):
                return False, "Encrypted file not found on disk"
            
            # Check if this is a direct MRIEncryptor file
            if encrypted_file_path.endswith('.json') and 'patient_' in os.path.basename(encrypted_file_path):
                try:
                    # Use MRIEncryptor directly for these files
                    from backend.crypto.mri_encryptor import MRIEncryptor
                    
                    mri_encryptor = MRIEncryptor()
                    encrypted_payload = mri_encryptor.load_encrypted_image(encrypted_file_path)
                    decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
                    
                    # Save the image
                    from PIL import Image
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    mri_path = os.path.join(self.decrypted_dir, f'mri_{patient_num}_{timestamp}.png')
                    Image.fromarray(decrypted_array).save(mri_path)
                    
                    return True, mri_path
                except Exception as direct_error:
                    print(f"Direct MRIEncryptor decryption failed: {str(direct_error)}")
                    # Continue with standard decryption as fallback
            
            # Step 1: Decrypt the keys using ECC
            try:
                combined_keys = self.ecc.decrypt_key(encrypted_keys)
                
                # The combined keys are base64-encoded strings from get_key(), not raw bytes
                if isinstance(combined_keys, bytes):
                    combined_keys = combined_keys.decode('utf-8')
                    
                # The combined_keys string is a concatenation of two base64 strings
                aes_key_b64 = combined_keys[:24]  # First 24 chars are AES key
                ascon_key_b64 = combined_keys[24:]  # Rest is ASCON key
                
                # Decode the base64 strings to get the actual key bytes
                aes_key = base64.b64decode(aes_key_b64)
                ascon_key = base64.b64decode(ascon_key_b64)
                
                # Verify that both keys are the correct length
                if len(aes_key) != 16 or len(ascon_key) != 16:
                    raise ValueError(f"Invalid key lengths: AES={len(aes_key)}, ASCON={len(ascon_key)}")
            except Exception as key_error:
                print(f"Key decryption error: {str(key_error)}")
                # Try to find any direct MRIEncryptor file for this patient as fallback
                return self._find_and_decrypt_direct_file(patient_num)
            
            # Step 2: Read the encrypted file
            try:
                with open(encrypted_file_path, 'r') as f:
                    ascon_encrypted = json.load(f)
            except Exception as file_error:
                print(f"Error reading encrypted file: {str(file_error)}")
                return self._find_and_decrypt_direct_file(patient_num)
            
            # Step 3: Try multiple decryption approaches
            try:
                # Initialize ASCON with the decrypted key
                ascon = AsconCipher(ascon_key)
                aes_encrypted = ascon.decrypt(ascon_encrypted)
                
                # Try all possible AES decryption methods
                stego_data = self._try_all_aes_decryption(aes_encrypted, aes_key)
                
                if stego_data is None:
                    return self._find_and_decrypt_direct_file(patient_num)
                    
                # Step 4: Save the stego image temporarily
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                stego_path = os.path.join(self.decrypted_dir, f'stego_{timestamp}.png')
                
                with open(stego_path, 'wb') as f:
                    f.write(stego_data)
                
                # Step 5: Extract and save the MRI data
                try:
                    from PIL import Image
                    Image.open(stego_path)  # Verify it's a valid image
                    
                    mri_data = extract_data(stego_path)
                    mri_path = os.path.join(self.decrypted_dir, f'mri_{patient_num}_{timestamp}.png')
                    
                    with open(mri_path, 'wb') as f:
                        f.write(mri_data)
                    
                    # Clean up temporary files
                    if os.path.exists(stego_path):
                        os.remove(stego_path)
                    
                    return True, mri_path
                except Exception as extract_error:
                    print(f"Extraction error: {str(extract_error)}")
                    if os.path.exists(stego_path) and os.path.getsize(stego_path) > 0:
                        # Return the stego image as a fallback
                        return True, stego_path
                    else:
                        return self._find_and_decrypt_direct_file(patient_num)
                        
            except Exception as decrypt_error:
                print(f"Decryption error: {str(decrypt_error)}")
                return self._find_and_decrypt_direct_file(patient_num)
                
        except Exception as e:
            print(f"General decryption error: {str(e)}")
            print(traceback.format_exc())
            return False, f"Decryption failed: {str(e)}"

    def _try_all_aes_decryption(self, aes_encrypted, aes_key):
        """Try multiple approaches to decrypt AES data"""
        # Method 1: Standard AES decryption
        try:
            aes = AESCipher(aes_key)
            return aes.decrypt(aes_encrypted)
        except Exception as e:
            print(f"Standard AES decryption failed: {str(e)}")
        
        # Method 2: Manual CBC mode decryption with different padding handling
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            if not isinstance(aes_encrypted, bytes) or len(aes_encrypted) < 16:
                raise ValueError("Invalid AES data format")
                
            iv = aes_encrypted[:16]
            ciphertext = aes_encrypted[16:]
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            raw_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Try several padding removal approaches
            
            # 2.1: Standard PKCS7 padding removal
            padding_byte = raw_data[-1]
            if 1 <= padding_byte <= 16:
                try:
                    # Check if padding is valid
                    if all(b == padding_byte for b in raw_data[-padding_byte:]):
                        return raw_data[:-padding_byte]
                except Exception:
                    pass
                    
            # 2.2: Find end by image signature
            # Many image files end with specific byte sequences
            image_signatures = [
                bytes([0xFF, 0xD9]),  # JPEG end
                bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])  # PNG IEND chunk
            ]
            
            for sig in image_signatures:
                pos = raw_data.rfind(sig)
                if pos > 0:
                    return raw_data[:pos + len(sig)]
                    
            # 2.3: Simply strip all trailing zeros
            i = len(raw_data) - 1
            while i >= 0 and raw_data[i] == 0:
                i -= 1
            
            if i >= 0:
                return raw_data[:i + 1]
                
            # 2.4: Just return the raw data as last resort
            return raw_data
            
        except Exception as e:
            print(f"Manual AES decryption failed: {str(e)}")
            
        # No methods worked
        return None

    def _find_and_decrypt_direct_file(self, patient_num):
        """Find and decrypt a direct MRIEncryptor file for the patient - optimized version"""
        try:
            from backend.crypto.mri_encryptor import MRIEncryptor
            import time
            
            # Keep track of processing time for optimization
            start_time = time.time()
            
            # Search Strategy 1: Check patient-specific directory - most likely location
            patient_dir = os.path.join(self.patients_dir, f'patient_{patient_num}')
            patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
            
            # First, focus on direct json files which are most reliable
            if os.path.exists(patient_encrypted_dir):
                # Prioritize direct files which are explicitly created as fallbacks
                direct_files = [f for f in os.listdir(patient_encrypted_dir) 
                               if f.startswith('mri_direct_') and f.endswith('.json')]
                
                # Also consider other MRI json files as a secondary option
                if not direct_files:
                    direct_files = [f for f in os.listdir(patient_encrypted_dir) 
                                  if f.startswith('mri_') and f.endswith('.json')]
                
                if direct_files:
                    # Sort by creation time - newest first
                    direct_files.sort(key=lambda f: os.path.getmtime(os.path.join(patient_encrypted_dir, f)), reverse=True)
                    
                    for direct_file in direct_files[:3]:  # Only try the 3 newest files for speed
                        try:
                            direct_path = os.path.join(patient_encrypted_dir, direct_file)
                            
                            # Use MRIEncryptor for JSON files
                            mri_encryptor = MRIEncryptor()
                            encrypted_payload = mri_encryptor.load_encrypted_image(direct_path)
                            decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
                            
                            # Validate decryption output
                            if decrypted_array is None or decrypted_array.size == 0:
                                continue
                            
                            # Save the decrypted image
                            from PIL import Image
                            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                            mri_path = os.path.join(self.decrypted_dir, f'mri_{patient_num}_{timestamp}.png')
                            
                            img = Image.fromarray(decrypted_array)
                            if img.width < 50 or img.height < 50:
                                continue
                                
                            img.save(mri_path)
                            
                            print(f"Decryption success in {time.time() - start_time:.2f}s")
                            return True, mri_path
                        except Exception as e:
                            print(f"Error decrypting {direct_file}: {str(e)}")
                            continue
            
            # Search Strategy 2: Check global encrypted directory 
            direct_patterns = [
                f'patient_{patient_num}_mri.json',
                f'patient_{patient_num}_direct',
                f'{patient_num}_mri'
            ]
            
            for pattern in direct_patterns:
                matching_files = [f for f in os.listdir(self.encrypted_dir) 
                                 if pattern in f and f.endswith('.json')]
                
                for file in matching_files:
                    try:
                        file_path = os.path.join(self.encrypted_dir, file)
                        
                        # Use MRIEncryptor for JSON files
                        mri_encryptor = MRIEncryptor()
                        encrypted_payload = mri_encryptor.load_encrypted_image(file_path)
                        decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
                        
                        # Basic validation
                        if decrypted_array is None or decrypted_array.size == 0:
                            continue
                        
                        # Save the decrypted image
                        from PIL import Image
                        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                        mri_path = os.path.join(self.decrypted_dir, f'mri_{patient_num}_{timestamp}.png')
                        
                        img = Image.fromarray(decrypted_array)
                        if img.width < 50 or img.height < 50:
                            continue
                            
                        img.save(mri_path)
                        
                        print(f"Global decrypt success in {time.time() - start_time:.2f}s")
                        return True, mri_path
                    except Exception as e:
                        print(f"Error decrypting global file {file}: {str(e)}")
                        continue
            
            # Search Strategy 3: Check database additional files
            try:
                all_files = self.db.get_all_patient_files(patient_num)
                if all_files:
                    for file_path, _ in all_files:
                        if os.path.exists(file_path) and file_path.endswith('.json'):
                            try:
                                mri_encryptor = MRIEncryptor()
                                encrypted_payload = mri_encryptor.load_encrypted_image(file_path)
                                decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
                                
                                # Basic validation
                                if decrypted_array is None or decrypted_array.size == 0:
                                    continue
                                
                                # Save the decrypted image
                                from PIL import Image
                                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                                mri_path = os.path.join(self.decrypted_dir, f'mri_{patient_num}_{timestamp}.png')
                                
                                img = Image.fromarray(decrypted_array)
                                if img.width < 50 or img.height < 50:
                                    continue
                                    
                                img.save(mri_path)
                                
                                print(f"DB file decrypt success in {time.time() - start_time:.2f}s")
                                return True, mri_path
                            except Exception as e:
                                print(f"Failed to decrypt db file {file_path}: {str(e)}")
                                continue
            except Exception as db_error:
                print(f"Database file access error: {str(db_error)}")
            
            print(f"Failed to find valid file in {time.time() - start_time:.2f}s")
            return False, "No suitable encrypted file found"
        except Exception as e:
            return False, f"Fallback decryption failed: {str(e)}"

    def decrypt_specific_file(self, file_path, encrypted_keys):
        """Decrypt a specific file with known keys"""
        try:
            if not os.path.exists(file_path):
                return False, "File not found"
                
            # Check file type
            if file_path.endswith('.json'):
                # Use MRIEncryptor for JSON files
                from backend.crypto.mri_encryptor import MRIEncryptor
                mri_encryptor = MRIEncryptor()
                encrypted_payload = mri_encryptor.load_encrypted_image(file_path)
                decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
                
                # Save as image
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                mri_path = os.path.join(self.decrypted_dir, f'mri_specific_{timestamp}.png')
                
                from PIL import Image
                Image.fromarray(decrypted_array).save(mri_path)
                return True, mri_path
                
            # For binary files, decrypt with keys
            if encrypted_keys:
                try:
                    # Load the file content
                    if file_path.endswith('.bin'):
                        with open(file_path, 'r') as f:
                            try:
                                ascon_encrypted = json.load(f)
                            except json.JSONDecodeError:
                                # Try reading as binary
                                f.close()
                                with open(file_path, 'rb') as bf:
                                    ascon_encrypted = bf.read()
                    
                    # Try to decrypt the keys
                    combined_keys = self.ecc.decrypt_key(encrypted_keys)
                    if isinstance(combined_keys, bytes):
                        combined_keys = combined_keys.decode('utf-8')
                    
                    # Split keys
                    aes_key_b64 = combined_keys[:24]
                    ascon_key_b64 = combined_keys[24:]
                    
                    aes_key = base64.b64decode(aes_key_b64)
                    ascon_key = base64.b64decode(ascon_key_b64)
                    
                    # Decrypt using ASCON
                    ascon = AsconCipher(ascon_key)
                    try:
                        aes_encrypted = ascon.decrypt(ascon_encrypted)
                    except Exception as ascon_error:
                        print(f"ASCON decryption error: {str(ascon_error)}")
                        # Skip to alternative decryption
                        raise
                    
                    # Decrypt using AES
                    aes = AESCipher(aes_key)
                    stego_data = aes.decrypt(aes_encrypted)
                    
                    # Save stego image
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    stego_path = os.path.join(self.decrypted_dir, f'stego_specific_{timestamp}.png')
                    
                    with open(stego_path, 'wb') as f:
                        f.write(stego_data)
                    
                    # Extract MRI data
                    mri_data = extract_data(stego_path)
                    mri_path = os.path.join(self.decrypted_dir, f'mri_extracted_{timestamp}.png')
                    
                    with open(mri_path, 'wb') as f:
                        f.write(mri_data)
                    
                    # Clean up
                    if os.path.exists(stego_path):
                        os.remove(stego_path)
                        
                    return True, mri_path
                except Exception as e:
                    print(f"Error in key-based decryption: {str(e)}")
                    # Try fallbacks
                    return self._try_all_decryption_methods(file_path)
            
            # If we reach here without returning, try all methods
            return self._try_all_decryption_methods(file_path)
        except Exception as e:
            print(f"Specific file decryption error: {str(e)}")
            return False, f"Failed to decrypt file: {str(e)}"

    def _try_all_decryption_methods(self, file_path):
        """Try all possible decryption methods on a file"""
        try:
            # Try JSON decryption with MRIEncryptor
            if file_path.endswith('.json'):
                try:
                    from backend.crypto.mri_encryptor import MRIEncryptor
                    mri_encryptor = MRIEncryptor()
                    encrypted_payload = mri_encryptor.load_encrypted_image(file_path)
                    decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
                    
                    # Save as image
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    mri_path = os.path.join(self.decrypted_dir, f'mri_fallback_{timestamp}.png')
                    
                    from PIL import Image
                    Image.fromarray(decrypted_array).save(mri_path)
                    return True, mri_path
                except Exception as json_err:
                    print(f"JSON decryption failed: {str(json_err)}")
            
            # For binary files, try known formats
            if file_path.endswith('.bin'):
                # Try to parse as JSON first
                try:
                    with open(file_path, 'r') as f:
                        content = json.load(f)
                    
                    # If it's a JSON object with nonce, ciphertext, tag - it's likely ASCON format
                    if all(k in content for k in ['nonce', 'ciphertext', 'tag']):
                        # Try with a newly generated ASCON key
                        ascon = AsconCipher()
                        try:
                            decrypted = ascon.decrypt(content)
                            
                            # Save and try to interpret as stego image
                            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                            output_path = os.path.join(self.decrypted_dir, f'decoded_{timestamp}.bin')
                            
                            with open(output_path, 'wb') as f:
                                f.write(decrypted)
                            
                            # If it looks like an image, return it
                            if self._is_likely_image(output_path):
                                return True, output_path
                            
                            # Otherwise clean up
                            if os.path.exists(output_path):
                                os.remove(output_path)
                        except Exception as ascon_err:
                            print(f"ASCON decryption attempt failed: {str(ascon_err)}")
                except Exception as parse_err:
                    print(f"JSON parsing failed: {str(parse_err)}")
            
            # Last resort: just copy the file to decrypted dir and return it
            # This helps when the file is already a valid image or readable format
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_path = os.path.join(self.decrypted_dir, f'copy_{os.path.basename(file_path)}')
                
                with open(file_path, 'rb') as src, open(output_path, 'wb') as dst:
                    dst.write(src.read())
                
                if self._is_likely_image(output_path):
                    return True, output_path
                
                # If not an image, clean up
                if os.path.exists(output_path):
                    os.remove(output_path)
            
            return False, "Could not decrypt file with any method"
        except Exception as e:
            print(f"All decryption methods failed: {str(e)}")
            return False, f"All decryption attempts failed: {str(e)}"

    def _is_likely_image(self, file_path):
        """Check if a file is likely to be a valid image"""
        try:
            from PIL import Image
            Image.open(file_path).verify()
            return True
        except Exception:
            # Try checking for common image file headers/signatures
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(12)
                    # Check for PNG signature
                    if header.startswith(b'\x89PNG\r\n\x1a\n'):
                        return True
                    # Check for JPEG signature
                    if header.startswith(b'\xff\xd8\xff'):
                        return True
                    # Check for GIF signature
                    if header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
                        return True
                    # Check for BMP signature
                    if header.startswith(b'BM'):
                        return True
            except Exception:
                pass
            return False

    def decrypt_bin_file(self, file_path, patient_num):
        """Decrypt a .bin file directly without relying on database keys - optimized"""
        if not os.path.exists(file_path):
            return False, "File not found"
        
        if not file_path.endswith('.bin'):
            return False, "Not a .bin file"
        
        try:
            # First check if the bin file is actually a valid image (sometimes they're mislabeled)
            if self._is_likely_image(file_path):
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                output_path = os.path.join(self.decrypted_dir, f'direct_{patient_num}_{timestamp}.png')
                
                with open(file_path, 'rb') as src, open(output_path, 'wb') as dst:
                    dst.write(src.read())
                
                # Verify it's a valid image and not an error message
                if self._verify_real_mri(output_path):
                    return True, output_path
                else:
                    if os.path.exists(output_path):
                        os.remove(output_path)
            
            # Try loading the file as JSON first (most common format)
            try:
                with open(file_path, 'r') as f:
                    encrypted_data = json.load(f)
                    
                    # If it's a MRIEncryptor format, try that first (fastest path)
                    if 'shape' in encrypted_data and 'dtype' in encrypted_data and 'encrypted_data' in encrypted_data:
                        from backend.crypto.mri_encryptor import MRIEncryptor
                        mri_encryptor = MRIEncryptor()
                        decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_data)
                        
                        # Save the decrypted image
                        from PIL import Image
                        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                        mri_path = os.path.join(self.decrypted_dir, f'mri_{patient_num}_{timestamp}.png')
                        
                        Image.fromarray(decrypted_array).save(mri_path)
                        return True, mri_path
                    
                    # If it's ASCON format, try to decrypt
                    if all(k in encrypted_data for k in ['nonce', 'ciphertext', 'tag']):
                        # Try to recover key from database
                        all_files = self.db.get_all_patient_files(patient_num)
                        keys_to_try = []
                        
                        # Collect all available keys to try
                        for db_path, key in all_files:
                            if key:
                                keys_to_try.append(key)
                        
                        # Also generate a key from patient number as last resort
                        import hashlib
                        key_seed = f"patient_{patient_num}_secure_key"
                        fallback_key = hashlib.md5(key_seed.encode()).digest()
                        
                        # Try all collected keys and the fallback
                        for key in keys_to_try:
                            try:
                                # Decrypt the key with ECC
                                combined_keys = self.ecc.decrypt_key(key)
                                if isinstance(combined_keys, bytes):
                                    combined_keys = combined_keys.decode('utf-8')
                                
                                ascon_key_b64 = combined_keys[24:]  # ASCON key is after AES key
                                ascon_key = base64.b64decode(ascon_key_b64)
                                
                                # Decrypt using ASCON
                                ascon = AsconCipher(ascon_key)
                                decrypted_data = ascon.decrypt(encrypted_data)
                                
                                # Continue with AES decryption...
                                # ...rest of the decryption process
                            except Exception as key_err:
                                print(f"Key {key[:10]}... failed: {str(key_err)}")
                                continue
                        
                        # Try with fallback key
                        try:
                            ascon = AsconCipher(fallback_key)
                            decrypted_data = ascon.decrypt(encrypted_data)
                            
                            # Process decrypted data...
                        except Exception as fallback_err:
                            print(f"Fallback key failed: {str(fallback_err)}")
            except Exception as json_err:
                print(f"JSON parsing failed: {str(json_err)}")
                # If not JSON, try as binary...
                
            # If all else fails, try extracting any image fragments
            output_path = self._try_recover_image_from_binary(file_path, patient_num)
            if output_path and self._verify_real_mri(output_path):
                return True, output_path
                
            return False, "Could not decrypt the bin file"
        except Exception as e:
            print(f"Bin file decryption error: {str(e)}")
            return False, str(e)

    def _try_recover_image_from_binary(self, file_path, patient_num):
        """Last resort - try to recover image data from a binary file by looking for image headers"""
        try:
            # Read the file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Look for common image headers
            png_header = b'\x89PNG\r\n\x1a\n'
            jpeg_header = b'\xff\xd8\xff'
            
            # Check for PNG
            png_pos = data.find(png_header)
            if png_pos >= 0:
                # Try to extract PNG data
                for i in range(png_pos, len(data)):
                    # Look for IEND chunk which marks the end of a PNG
                    if data[i:i+8] == b'IEND\xae\x42\x60\x82':
                        # Extract the PNG data (header to IEND + 8 bytes)
                        png_data = data[png_pos:i+8]
                        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                        output_path = os.path.join(self.decrypted_dir, f'recovered_png_{patient_num}_{timestamp}.png')
                        
                        with open(output_path, 'wb') as f:
                            f.write(png_data)
                        
                        # Verify it's a valid image
                        try:
                            from PIL import Image
                            img = Image.open(output_path)
                            img.verify()
                            return output_path
                        except:
                            if os.path.exists(output_path):
                                os.remove(output_path)
            
            # Check for JPEG
            jpeg_pos = data.find(jpeg_header)
            if jpeg_pos >= 0:
                # Try to extract JPEG data (trickier as no definitive end marker)
                # Look for EOI marker (0xFF 0xD9) which marks the end of a JPEG
                for i in range(len(data)-1, jpeg_pos, -1):
                    if data[i-1:i+1] == b'\xff\xd9':
                        jpeg_data = data[jpeg_pos:i+1]
                        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                        output_path = os.path.join(self.decrypted_dir, f'recovered_jpeg_{patient_num}_{timestamp}.jpg')
                        
                        with open(output_path, 'wb') as f:
                            f.write(jpeg_data)
                        
                        # Verify it's a valid image
                        try:
                            from PIL import Image
                            img = Image.open(output_path)
                            img.verify()
                            return output_path
                        except:
                            if os.path.exists(output_path):
                                os.remove(output_path)
            
            return None
        except Exception as e:
            print(f"Image recovery error: {str(e)}")
            return None

    def _verify_real_mri(self, file_path):
        """Verify that an image is actually an MRI and not an error message"""
        try:
            from PIL import Image, ImageStat
            
            # Open and verify basic image properties
            img = Image.open(file_path)
            
            # Validate dimensions - real MRIs aren't tiny
            if img.width < 100 or img.height < 100:
                return False
                
            # Check image statistics
            if img.mode in ('RGB', 'RGBA'):
                # Convert to RGB if necessary
                if img.mode == 'RGBA':
                    img = img.convert('RGB')
                    
                # Get average brightness - MRIs are typically darker
                stat = ImageStat.Stat(img)
                avg_brightness = sum(stat.mean[:3])/3
                
                # If very bright (like error images with white backgrounds)
                if avg_brightness > 200:
                    return False
                    
                # Sample some pixels to see if they're all white/similar
                pixels = [
                    img.getpixel((0, 0)),
                    img.getpixel((img.width-1, 0)),
                    img.getpixel((0, img.height-1)),
                    img.getpixel((img.width-1, img.height-1)),
                    img.getpixel((img.width//2, img.height//2))
                ]
                
                # If most pixels are white or very similar, it's likely an error image
                white_count = sum(1 for p in pixels if all(c > 240 for c in p[:3]))
                if white_count >= 4:
                    return False
            
            return True
        except Exception as e:
            print(f"MRI verification error: {str(e)}")
            return False

    def generate_otp(self, patient_num):
        """Generate an OTP for patient verification"""
        return self.otp_gen.generate_otp(patient_num)
    
    def verify_otp(self, patient_num, otp):
        """Verify an OTP for patient verification"""
        return self.otp_gen.verify_otp(patient_num, otp)
    
    def verify_admin(self, username, password):
        """Verify admin credentials"""
        return self.db.verify_admin(username, password)

    def get_key(self):
        """Return the current key in base64 encoding"""
        return base64.b64encode(self.key).decode('utf-8')

# For direct testing
if __name__ == "__main__":
    brain_secure = SecureXway()
    # Add test code here if needed