# backend/database/db_handler.py
import sqlite3
import os
import base64
from datetime import datetime

class DatabaseHandler:
    def __init__(self, db_file='securexway.db'):
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
        
        # Create additional_files table for fallback files
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS additional_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_num TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_num) REFERENCES patients (patient_num)
        )
        ''')
        
        # Alter encrypted_files table if patient_file_path column doesn't exist
        try:
            cursor.execute("SELECT patient_file_path FROM encrypted_files LIMIT 1")
        except sqlite3.OperationalError:
            # Column doesn't exist, add it
            cursor.execute("ALTER TABLE encrypted_files ADD COLUMN patient_file_path TEXT")
        
        # Insert default admin user if not exists
        cursor.execute("SELECT * FROM users WHERE username = 'Admin'")
        if not cursor.fetchone():
            # Password: admin123 (in a real app, this would be hashed)
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         ('Admin', 'admin123', 'admin'))
        
        # Insert default regular user if not exists
        cursor.execute("SELECT * FROM users WHERE username = 'user'")
        if not cursor.fetchone():
            # Password: user123 (in a real app, this would be hashed)
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         ('user', 'user123', 'user'))
        
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
    
    def store_encrypted_file(self, patient_num, file_path, encrypted_key, patient_file_path=None):
        """Store information about an encrypted file"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Handle both string and bytes input for encrypted_key
        if isinstance(encrypted_key, str):
            # Already a string, no need to encode
            encrypted_key_str = encrypted_key
        else:
            # Convert bytes to string for storage
            encrypted_key_str = base64.b64encode(encrypted_key).decode('utf-8')
            
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Check if patient exists, add if not
            cursor.execute("SELECT * FROM patients WHERE patient_num = ?", (patient_num,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO patients (patient_num) VALUES (?)", (patient_num,))
            
            # Check if file already exists for this patient
            cursor.execute("SELECT id FROM encrypted_files WHERE patient_num = ?", (patient_num,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                if patient_file_path:
                    cursor.execute(
                        "UPDATE encrypted_files SET file_path = ?, encrypted_key = ?, patient_file_path = ?, created_at = ? WHERE patient_num = ?",
                        (file_path, encrypted_key_str, patient_file_path, created_at, patient_num)
                    )
                else:
                    cursor.execute(
                        "UPDATE encrypted_files SET file_path = ?, encrypted_key = ?, created_at = ? WHERE patient_num = ?",
                        (file_path, encrypted_key_str, created_at, patient_num)
                    )
            else:
                # Insert new record
                if patient_file_path:
                    cursor.execute(
                        "INSERT INTO encrypted_files (patient_num, file_path, encrypted_key, patient_file_path, created_at) VALUES (?, ?, ?, ?, ?)",
                        (patient_num, file_path, encrypted_key_str, patient_file_path, created_at)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO encrypted_files (patient_num, file_path, encrypted_key, created_at) VALUES (?, ?, ?, ?)",
                        (patient_num, file_path, encrypted_key_str, created_at)
                    )
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error storing encrypted file: {e}")
            return False
        finally:
            conn.close()

    def store_additional_file(self, patient_num, file_path):
        """Store additional file for a patient (for fallback)"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            # Check if patient exists, add if not
            cursor.execute("SELECT * FROM patients WHERE patient_num = ?", (patient_num,))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO patients (patient_num) VALUES (?)", (patient_num,))
            
            # Insert additional file record
            cursor.execute(
                "INSERT INTO additional_files (patient_num, file_path) VALUES (?, ?)",
                (patient_num, file_path)
            )
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error storing additional file: {e}")
            return False
        finally:
            conn.close()
    
    def get_encrypted_file(self, patient_num):
        """Retrieve the most recent encrypted file for a patient"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            # First try: exact match on patient_num
            cursor.execute(
                "SELECT file_path, encrypted_key, patient_file_path FROM encrypted_files WHERE patient_num = ? ORDER BY created_at DESC LIMIT 1",
                (patient_num,)
            )
            result = cursor.fetchone()
            
            if result and len(result) >= 2:
                file_path, encrypted_key_str = result[0], result[1]
                patient_file_path = result[2] if len(result) > 2 else None
                
                # If patient_file_path exists and is accessible, use it instead
                if patient_file_path and os.path.exists(patient_file_path):
                    return patient_file_path, encrypted_key_str
                
                # Otherwise return the regular file path
                if os.path.exists(file_path):
                    return file_path, encrypted_key_str
            
            # Second try: LIKE query with pattern matching
            cursor.execute(
                "SELECT file_path, encrypted_key, patient_file_path FROM encrypted_files WHERE patient_num LIKE ? ORDER BY created_at DESC LIMIT 1",
                (f"%{patient_num}%",)
            )
            result = cursor.fetchone()
            
            if result and len(result) >= 2:
                file_path, encrypted_key_str = result[0], result[1]
                patient_file_path = result[2] if len(result) > 2 else None
                
                # If patient_file_path exists and is accessible, use it instead
                if patient_file_path and os.path.exists(patient_file_path):
                    return patient_file_path, encrypted_key_str
                
                # Otherwise return the regular file path
                if os.path.exists(file_path):
                    return file_path, encrypted_key_str
            
            # Third try: Check additional_files table
            cursor.execute(
                "SELECT file_path FROM additional_files WHERE patient_num = ? OR patient_num LIKE ? ORDER BY created_at DESC LIMIT 1",
                (patient_num, f"%{patient_num}%")
            )
            result = cursor.fetchone()
            
            if result:
                file_path = result[0]
                if os.path.exists(file_path):
                    # For direct files like JSON, we don't need an encryption key
                    return file_path, None
            
            # Fourth try: Check if patient directory exists
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_num}')
            patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
            
            if os.path.exists(patient_encrypted_dir):
                files = sorted([f for f in os.listdir(patient_encrypted_dir) 
                               if f.startswith('mri_')], reverse=True)
                if files:
                    # Return the newest file
                    newest_file = os.path.join(patient_encrypted_dir, files[0])
                    return newest_file, None
            
            # If we get here, no file was found
            return None, None
        finally:
            conn.close()

    def get_all_patient_files(self, patient_num):
        """Get all encrypted files for a patient (useful for fallback)"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        all_files = []
        
        try:
            # Get files from encrypted_files table
            cursor.execute(
                "SELECT file_path, encrypted_key, patient_file_path FROM encrypted_files WHERE patient_num = ? OR patient_num LIKE ? ORDER BY created_at DESC",
                (patient_num, f"%{patient_num}%")
            )
            results = cursor.fetchall()
            
            for result in results:
                file_path, encrypted_key_str = result[0], result[1]
                patient_file_path = result[2] if len(result) > 2 else None
                
                if patient_file_path and os.path.exists(patient_file_path):
                    all_files.append((patient_file_path, encrypted_key_str))
                
                if os.path.exists(file_path):
                    all_files.append((file_path, encrypted_key_str))
            
            # Get files from additional_files table
            cursor.execute(
                "SELECT file_path FROM additional_files WHERE patient_num = ? OR patient_num LIKE ? ORDER BY created_at DESC",
                (patient_num, f"%{patient_num}%")
            )
            results = cursor.fetchall()
            
            for result in results:
                file_path = result[0]
                if os.path.exists(file_path):
                    all_files.append((file_path, None))
            
            # Check patient directory
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_num}')
            patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
            
            if os.path.exists(patient_encrypted_dir):
                for file in os.listdir(patient_encrypted_dir):
                    if file.startswith('mri_'):
                        file_path = os.path.join(patient_encrypted_dir, file)
                        all_files.append((file_path, None))
            
            return all_files
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
    
    def verify_user(self, username, password):
        """Verify user credentials"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password = ? AND role = 'user'",
                (username, password)
            )
            return cursor.fetchone() is not None
        finally:
            conn.close()

    def find_patient_records_like(self, patient_num):
        """Find all records that might match a patient number"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        results = []
        
        try:
            # Look in encrypted_files
            cursor.execute(
                "SELECT patient_num, file_path, encrypted_key FROM encrypted_files WHERE patient_num LIKE ? ORDER BY created_at DESC",
                (f"%{patient_num}%",)
            )
            enc_files = cursor.fetchall()
            for record in enc_files:
                patient_id, file_path, key = record
                if os.path.exists(file_path):
                    results.append({
                        'table': 'encrypted_files',
                        'patient_num': patient_id,
                        'file_path': file_path,
                        'key': key
                    })
            
            # Look in additional_files
            cursor.execute(
                "SELECT patient_num, file_path FROM additional_files WHERE patient_num LIKE ? ORDER BY created_at DESC",
                (f"%{patient_num}%",)
            )
            add_files = cursor.fetchall()
            for record in add_files:
                patient_id, file_path = record
                if os.path.exists(file_path):
                    results.append({
                        'table': 'additional_files',
                        'patient_num': patient_id,
                        'file_path': file_path
                    })
            
            # Just get all patient numbers as last resort
            if not results:
                cursor.execute("SELECT patient_num FROM patients")
                all_patients = cursor.fetchall()
                for patient in all_patients:
                    pat_num = patient[0]
                    # Try to find similar patient numbers based on string distance
                    if len(patient_num) >= 3 and len(pat_num) >= 3:
                        # Simple overlap check - at least 3 characters in common
                        if patient_num in pat_num or pat_num in patient_num:
                            results.append({
                                'table': 'patients',
                                'patient_num': pat_num
                            })
            
            # Add a simple string similarity function to better match patient numbers
            def similarity_score(a, b):
                """Simple string similarity score - higher is more similar"""
                if a == b:
                    return 100  # Exact match is best
                
                # Count common characters
                common = 0
                for char in a:
                    if char in b:
                        common += 1
                
                # Normalize by length
                sim = (common * 100) / max(len(a), len(b))
                
                # Bonus points for same length
                if len(a) == len(b):
                    sim += 10
                    
                # Bonus points for sharing prefix or suffix
                prefix_len = 0
                for i in range(min(len(a), len(b))):
                    if a[i] == b[i]:
                        prefix_len += 1
                    else:
                        break
                
                suffix_len = 0
                for i in range(1, min(len(a), len(b)) + 1):
                    if a[-i] == b[-i]:
                        suffix_len += 1
                    else:
                        break
                        
                sim += (prefix_len + suffix_len) * 5
                
                return sim

            # Sort results by similarity to requested patient number
            if results and patient_num:
                results.sort(key=lambda x: similarity_score(x.get('patient_num', ''), patient_num), reverse=True)
            
            return results
        finally:
            conn.close()

    def execute_query(self, query, params=None):
        """
        Execute a generic SQL query with optional parameters
        
        Parameters:
        -----------
        query : str
            SQL query to execute
        params : tuple, optional
            Parameters for the query
            
        Returns:
        --------
        list
            Query results as a list of tuples
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            conn.commit()
            
            # If it's a SELECT query, return the results
            if query.strip().upper().startswith('SELECT'):
                return cursor.fetchall()
            return []
        except Exception as e:
            print(f"Database error executing '{query}': {str(e)}")
            raise
        finally:
            conn.close()

    def store_patient_email(self, patient_num, email):
        """
        Store a patient's email address
        
        Parameters:
        -----------
        patient_num : str
            Patient ID number
        email : str
            Patient's email address
            
        Returns:
        --------
        bool
            True if successful, False otherwise
        """
        try:
            # Ensure the patient_emails table exists
            self.execute_query(
                "CREATE TABLE IF NOT EXISTS patient_emails (patient_num TEXT PRIMARY KEY, email TEXT)"
            )
            
            # Store or update the email
            self.execute_query(
                "INSERT OR REPLACE INTO patient_emails (patient_num, email) VALUES (?, ?)",
                (patient_num, email)
            )
            return True
        except Exception as e:
            print(f"Failed to store patient email: {str(e)}")
            return False

    def get_patient_email(self, patient_num):
        """
        Get a patient's email address
        
        Parameters:
        -----------
        patient_num : str
            Patient ID number
            
        Returns:
        --------
        str or None
            Patient's email address if found, None otherwise
        """
        try:
            result = self.execute_query(
                "SELECT email FROM patient_emails WHERE patient_num = ?",
                (patient_num,)
            )
            if result and result[0]:
                return result[0][0]
            return None
        except Exception as e:
            print(f"Failed to retrieve patient email: {str(e)}")
            return None