# backend/utils/__init__.py
# Empty __init__.py file to make the directory a package

# backend/utils/image_handler.py
import os
from PIL import Image
import io
import numpy as np

def is_valid_image(file_path):
    """Check if the file is a valid image"""
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except:
        return False

def convert_to_bytes(image_path):
    """Convert an image to bytes"""
    with open(image_path, 'rb') as f:
        return f.read()

def convert_from_bytes(image_bytes, output_path=None):
    """Convert bytes to an image"""
    img = Image.open(io.BytesIO(image_bytes))
    if output_path:
        img.save(output_path)
        return output_path
    return img

def resize_image(image_path, max_size=(800, 800), output_path=None):
    """Resize an image while maintaining aspect ratio"""
    img = Image.open(image_path)
    img.thumbnail(max_size)
    
    if output_path:
        img.save(output_path)
        return output_path
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format=img.format)
    return img_byte_arr.getvalue()

# backend/utils/otp_generator.py
import random
import time
import hashlib

class OTPGenerator:
    def __init__(self, expiry_time=300):  # Default expiry time: 5 minutes
        self.expiry_time = expiry_time
        self.active_otps = {}  # {patient_num: {'otp': OTP, 'timestamp': timestamp}}
    
    def generate_otp(self, patient_num, length=6):
        """Generate a new OTP for a patient number"""
        # Generate a random OTP
        otp = ''.join([str(random.randint(0, 9)) for _ in range(length)])
        
        # Store the OTP with timestamp
        self.active_otps[patient_num] = {
            'otp': otp,
            'timestamp': time.time()
        }
        
        return otp
    
    def verify_otp(self, patient_num, otp):
        """Verify if the OTP is valid for the patient number"""
        if patient_num not in self.active_otps:
            return False
        
        stored_otp = self.active_otps[patient_num]
        current_time = time.time()
        
        # Check if OTP is expired
        if current_time - stored_otp['timestamp'] > self.expiry_time:
            # Remove expired OTP
            del self.active_otps[patient_num]
            return False
        
        # Check if OTP matches
        if stored_otp['otp'] == otp:
            # Remove used OTP
            del self.active_otps[patient_num]
            return True
        
        return False

# backend/database/__init__.py
# Empty __init__.py file to make the directory a package

# backend/database/db_handler.py
import sqlite3
import os
import json
import base64
from datetime import datetime

class DatabaseHandler:
    def __init__(self, db_file='brainsecurex.db'):
        self.db_file = db_file
        self.initialize_db()
    
    def initialize_db(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create patients table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_num TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create encrypted_files table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_num TEXT NOT NULL,
            file_path TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_num) REFERENCES patients (patient_num)
        )
        ''')
        
        # Insert default admin user if not exists
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            # Password: admin123 (in a real app, this would be hashed)
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         ('admin', 'admin123', 'admin'))
        
        conn.commit()
        conn.close()
    
    def add_patient(self, patient_num):
        """Add a new patient to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO patients (patient_num) VALUES (?)", (patient_num,))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Patient already exists
            return False
        finally:
            conn.close()
    
    def store_encrypted_file(self, patient_num, file_path, encrypted_key):
        """Store information about an encrypted file"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Convert encrypted key to string for storage
        encrypted_key_str = base64.b64encode(encrypted_key).decode('utf-8')
        
        try:
            # Check if patient exists, add if not
            cursor.execute("SELECT * FROM patients WHERE patient_num = ?", (patient_num,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO patients (patient_num) VALUES (?)", (patient_num,))
            
            # Store file information
            cursor.execute(
                "INSERT INTO encrypted_files (patient_num, file_path, encrypted_key) VALUES (?, ?, ?)",
                (patient_num, file_path, encrypted_key_str)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error storing encrypted file: {e}")
            return False
        finally:
            conn.close()
    
    def get_encrypted_file(self, patient_num):
        """Retrieve the most recent encrypted file for a patient"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT file_path, encrypted_key FROM encrypted_files WHERE patient_num = ? ORDER BY created_at DESC LIMIT 1",
                (patient_num,)
            )
            result = cursor.fetchone()
            
            if result:
                file_path, encrypted_key_str = result
                # Convert the stored string back to bytes
                encrypted_key = base64.b64decode(encrypted_key_str)
                return file_path, encrypted_key
            return None, None
        finally:
            conn.close()
    
    def verify_admin(self, username, password):
        """Verify admin credentials"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password = ? AND role = 'admin'",
                (username, password)
            )
            return cursor.fetchone() is not None
        finally:
            conn.close()