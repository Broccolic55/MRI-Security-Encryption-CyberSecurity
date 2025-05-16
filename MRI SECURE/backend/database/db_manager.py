# backend/database/db_manager.py
import os
import sqlite3
import json

class DatabaseManager:
    """Database manager for SecureXway"""
    
    def __init__(self, db_path="secure_x.db"):
        """Initialize the database manager"""
        self.db_path = db_path
        
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize the database
        self._init_db()
    
    def _init_db(self):
        """Initialize the database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS encrypted_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patient_num TEXT UNIQUE,
                    file_path TEXT,
                    encrypted_keys TEXT,
                    created_at TEXT
                )
            ''')
            
            # Sample admin table (in a real system, use proper password hashing)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    created_at TEXT
                )
            ''')
            
            conn.commit()
    
    def store_encrypted_file(self, patient_num, file_path, encrypted_keys, created_at):
        """
        Store information about an encrypted file
        
        Args:
            patient_num (str): Patient identification number
            file_path (str): Path to the encrypted file
            encrypted_keys (str): Encrypted encryption keys
            created_at (str): Creation timestamp
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if patient already exists
            cursor.execute(
                "SELECT id FROM encrypted_files WHERE patient_num = ?", 
                (patient_num,)
            )
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                cursor.execute(
                    "UPDATE encrypted_files SET file_path = ?, encrypted_keys = ?, created_at = ? WHERE patient_num = ?",
                    (file_path, encrypted_keys, created_at, patient_num)
                )
            else:
                # Insert new record
                cursor.execute(
                    "INSERT INTO encrypted_files (patient_num, file_path, encrypted_keys, created_at) VALUES (?, ?, ?, ?)",
                    (patient_num, file_path, encrypted_keys, created_at)
                )
            
            conn.commit()
    
    def get_encrypted_file(self, patient_num):
        """
        Get information about an encrypted file
        
        Args:
            patient_num (str): Patient identification number
            
        Returns:
            tuple: (file_path, encrypted_keys) or (None, None) if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT file_path, encrypted_keys FROM encrypted_files WHERE patient_num = ?", 
                (patient_num,)
            )
            result = cursor.fetchone()
            
            if result:
                return result
            else:
                return None, None
    
    def delete_encrypted_file(self, patient_num):
        """
        Delete information about an encrypted file
        
        Args:
            patient_num (str): Patient identification number
            
        Returns:
            bool: True if deleted, False if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                "DELETE FROM encrypted_files WHERE patient_num = ?", 
                (patient_num,)
            )
            
            conn.commit()
            return cursor.rowcount > 0