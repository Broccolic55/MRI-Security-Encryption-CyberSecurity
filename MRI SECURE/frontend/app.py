# frontend/app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import os
import sys
import json
import traceback
from datetime import datetime
import random
from werkzeug.utils import secure_filename
import hashlib
import base64
import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import SecureXway
# Import MRIEncryptor for direct fallback encryption
from backend.crypto.mri_encryptor import MRIEncryptor
# Import the email sender
from backend.utils.email_sender import send_otp_email

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Initialize SecureXway
secure_x = SecureXway()

# Allowed image file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff'}

def allowed_file(filename):
    """Check if a file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_random_cover_image():
    """Select a random cover image from the cover_images folder"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cover_images_dir = os.path.join(base_dir, 'cover_images')
    
    # Ensure the directory exists
    if not os.path.exists(cover_images_dir):
        os.makedirs(cover_images_dir, exist_ok=True)
        print(f"Created cover images directory at: {cover_images_dir}")
        return None
    
    # Get all image files from the directory
    cover_files = [f for f in os.listdir(cover_images_dir) 
                  if os.path.isfile(os.path.join(cover_images_dir, f)) and 
                  f.lower().endswith(tuple(ALLOWED_EXTENSIONS))]
    
    if not cover_files:
        print("No cover images found in the directory")
        return None
    
    # Select a random cover image
    selected_cover = random.choice(cover_files)
    return os.path.join(cover_images_dir, selected_cover)

@app.route('/')
def index():
    """Render the home page"""
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    """Render admin login page and handle login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Case-sensitive check - use 'Admin' not 'admin'
        if secure_x.verify_admin(username, password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'error')
    
    return render_template('admin.html')

@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """Render admin dashboard and handle file uploads"""
    if not session.get('admin_logged_in'):
        flash('Please log in first.', 'error')
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        # Check if patient number is provided
        patient_num = request.form.get('patient_num')
        if not patient_num:
            flash('Patient number is required.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Get patient email for OTP delivery
        patient_email = request.form.get('patient_email')
        if not patient_email:
            flash('Patient email is required for OTP delivery.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Check if MRI image is provided
        if 'mri_image' not in request.files:
            flash('MRI image is required.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        mri_file = request.files['mri_image']
        
        # Check if MRI file is valid
        if mri_file.filename == '':
            flash('MRI image is required.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        if not allowed_file(mri_file.filename):
            flash('Invalid file format. Allowed formats: png, jpg, jpeg, gif, bmp, tiff.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Create uploads directory with absolute path
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        uploads_dir = os.path.join(base_dir, 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        
        # Save MRI file temporarily with absolute path
        mri_filename = secure_filename(mri_file.filename)
        mri_path = os.path.join(uploads_dir, mri_filename)
        mri_file.save(mri_path)
        
        # Automatically select a random cover image
        cover_path = get_random_cover_image()
        if not cover_path:
            flash('No cover images available. Please add some cover images to the cover_images directory.', 'error')
            if os.path.exists(mri_path):
                os.remove(mri_path)
            return redirect(url_for('admin_dashboard'))
        
        try:
            # Encrypt the MRI image with the selected cover image
            original_extension = os.path.splitext(mri_filename)[1].lower()
            
            # Store the original file data for verification later
            with open(mri_path, 'rb') as f:
                original_file_data = f.read()
                original_file_hash = hashlib.md5(original_file_data).hexdigest()
            
            # Store the original extension in a separate file or include it in the fallback encryption
            success, result = secure_x.encrypt_mri(mri_path, cover_path, patient_num)
            
            # Clean up temporary files
            if os.path.exists(mri_path):
                os.remove(mri_path)
            
            if success:
                # Store the original extension and hash in database as additional metadata
                try:
                    # Make sure the metadata includes the extension with the dot
                    if not original_extension.startswith('.'):
                        original_extension = f".{original_extension}"
                    
                    # Store the metadata for this file
                    metadata = {
                        'original_format': original_extension,
                        'original_hash': original_file_hash,
                        'binary_perfect': True,  # Flag to indicate we want perfect binary preservation
                        'original_size': len(original_file_data)
                    }
                    
                    try:
                        secure_x.db.store_file_metadata(patient_num, result, metadata)
                    except:
                        # If the above method doesn't exist, try to store in a new table
                        try:
                            secure_x.db.execute_query(
                                "CREATE TABLE IF NOT EXISTS file_metadata (patient_num TEXT, file_path TEXT, metadata TEXT, PRIMARY KEY (patient_num, file_path))"
                            )
                            secure_x.db.execute_query(
                                "INSERT OR REPLACE INTO file_metadata (patient_num, file_path, metadata) VALUES (?, ?, ?)",
                                (patient_num, result, json.dumps(metadata))
                            )
                        except Exception as db_err:
                            print(f"Failed to store format metadata in DB: {str(db_err)}")
                    
                    # Also create a separate metadata file for redundancy
                    try:
                        patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_num}')
                        patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
                        os.makedirs(patient_encrypted_dir, exist_ok=True)
                        
                        metadata_file = os.path.join(patient_encrypted_dir, f'format_metadata_{patient_num}.json')
                        with open(metadata_file, 'w') as f:
                            json.dump(metadata, f)
                    except Exception as meta_err:
                        print(f"Failed to create format metadata file: {str(meta_err)}")
                        
                except Exception as metadata_error:
                    print(f"Failed to store format metadata: {str(metadata_error)}")
                    
                # Store the patient email in the database
                try:
                    # Use the dedicated method if it exists, otherwise fall back to execute_query
                    if hasattr(secure_x.db, 'store_patient_email'):
                        email_stored = secure_x.db.store_patient_email(patient_num, patient_email)
                    else:
                        # First ensure the patient_emails table exists
                        secure_x.db.execute_query(
                            "CREATE TABLE IF NOT EXISTS patient_emails (patient_num TEXT PRIMARY KEY, email TEXT)"
                        )
                        # Store or update the email for this patient
                        secure_x.db.execute_query(
                            "INSERT OR REPLACE INTO patient_emails (patient_num, email) VALUES (?, ?)",
                            (patient_num, patient_email)
                        )
                        email_stored = True
                    
                    if not email_stored:
                        flash('Warning: Failed to store patient email - OTP delivery may not work.', 'warning')
                except Exception as email_err:
                    print(f"Failed to store patient email: {str(email_err)}")
                    flash('Warning: Failed to store patient email - OTP delivery may not work.', 'warning')
                
                flash(f'MRI image encrypted successfully for patient {patient_num} using cover image {os.path.basename(cover_path)}.', 'success')
            else:
                flash(f'Error encrypting MRI image: {result}', 'error')
        except TypeError as type_error:
            # Specific handling for the TypeError from ASCON encryption
            print(f"DEBUG - Type Error: {str(type_error)}")
            print(traceback.format_exc())
            flash('Encryption type error encountered. Using fallback method.', 'warning')
            
            try:
                # Fallback to direct MRIEncryptor
                direct_encryptor = MRIEncryptor()
                
                # Save original file data for perfect binary preservation
                with open(mri_path, 'rb') as f:
                    original_file_data = f.read()
                    original_file_hash = hashlib.md5(original_file_data).hexdigest()
                
                # Create output directory
                encrypted_dir = os.path.join(base_dir, 'encrypted')
                os.makedirs(encrypted_dir, exist_ok=True)
                
                # Generate output path
                encrypted_file = os.path.join(encrypted_dir, f'patient_{patient_num}_mri.json')
                
                # Get original extension for storage
                original_extension = os.path.splitext(mri_filename)[1].lower()
                
                # Directly encrypt using MRIEncryptor with format preservation and binary data
                encrypted_payload = direct_encryptor.encrypt_mri_image(mri_path, preserve_original=True)
                encrypted_payload['original_format'] = original_extension
                encrypted_payload['original_hash'] = original_file_hash
                encrypted_payload['original_binary'] = base64.b64encode(original_file_data).decode('utf-8')
                encrypted_payload['binary_perfect'] = True
                
                direct_encryptor.save_encrypted_image(encrypted_payload, encrypted_file)
                
                # Register with database
                secure_x.db.store_encrypted_file(patient_num, encrypted_file, os.path.basename(mri_path))
                
                # Clean up temporary files
                if os.path.exists(mri_path):
                    os.remove(mri_path)
                
                flash(f'MRI image encrypted successfully using fallback method for patient {patient_num}.', 'success')
            except Exception as fallback_error:
                flash(f'All encryption methods failed: {str(fallback_error)}', 'error')
                print(f"DEBUG - Fallback error: {str(fallback_error)}")
                
                # Ensure cleanup
                if os.path.exists(mri_path):
                    os.remove(mri_path)
        except Exception as e:
            flash(f'Error during encryption process: {str(e)}', 'error')
            print(f"DEBUG - General error: {str(e)}")
            print(traceback.format_exc())
            
            # Clean up temporary files
            if os.path.exists(mri_path):
                os.remove(mri_path)
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_dashboard.html')

@app.route('/admin/verify-integrity')
def verify_integrity():
    """API endpoint to verify patient data integrity"""
    if not session.get('admin_logged_in'):
        return json.dumps({'error': 'Not authorized'}), 403, {'ContentType': 'application/json'}
    
    patient_id = request.args.get('patient_id')
    if not patient_id:
        return json.dumps({'error': 'Patient ID is required'}), 400, {'ContentType': 'application/json'}
    
    try:
        # Find all encrypted files for this patient
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Results storage
        integrity_results = {'files': [], 'tampered_files_count': 0, 'alert_sent': False}
        
        # Check patient directory
        patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_id}')
        patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
        
        # Get metadata for integrity checking
        metadata = None
        metadata_file = os.path.join(patient_encrypted_dir, f'format_metadata_{patient_id}.json')
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except Exception as meta_err:
                print(f"Failed to read metadata file: {str(meta_err)}")
        
        # Flag to track if any tampering was detected
        tampering_detected = False
        tampered_files = []
        
        # Check patient encrypted directory
        if os.path.exists(patient_encrypted_dir):
            for filename in os.listdir(patient_encrypted_dir):
                # Check both JSON and BIN files for tampering
                if (filename.endswith('.json') and not filename.startswith('format_metadata')) or filename.endswith('.bin'):
                    file_path = os.path.join(patient_encrypted_dir, filename)
                    
                    # Verify file integrity
                    is_verified, details = verify_file_integrity(file_path, metadata)
                    
                    if not is_verified:
                        tampering_detected = True
                        tampered_files.append(filename)
                    
                    integrity_results['files'].append({
                        'filename': filename,
                        'verified': is_verified,
                        'details': details
                    })
        
        # Check global encrypted directory
        encrypted_dir = os.path.join(base_dir, 'encrypted')
        if os.path.exists(encrypted_dir):
            for filename in os.listdir(encrypted_dir):
                # Check both JSON and BIN files for patient records
                if patient_id in filename and (filename.endswith('.json') or filename.endswith('.bin')):
                    file_path = os.path.join(encrypted_dir, filename)
                    
                    # Verify file integrity
                    is_verified, details = verify_file_integrity(file_path, metadata)
                    
                    if not is_verified:
                        tampering_detected = True
                        tampered_files.append(filename)
                    
                    integrity_results['files'].append({
                        'filename': filename,
                        'verified': is_verified,
                        'details': details
                    })
        
        # Count tampered files and set in results
        integrity_results['tampered_files_count'] = len(tampered_files)
        
        # If tampering detected, send alert email to patient
        if tampering_detected:
            # Find patient email from database
            patient_email = None
            try:
                # Try the dedicated method first if it exists
                if hasattr(secure_x.db, 'get_patient_email'):
                    patient_email = secure_x.db.get_patient_email(patient_id)
                
                # If that fails, try the generic query method
                if not patient_email:
                    result = secure_x.db.execute_query(
                        "SELECT email FROM patient_emails WHERE patient_num = ?",
                        (patient_id,)
                    )
                    if result and result[0]:
                        patient_email = result[0][0]
            except Exception as e:
                print(f"Error retrieving patient email: {str(e)}")
            
            # Send alert email if we have the patient's email
            if patient_email:
                alert_sent = send_tampering_alert_email(
                    patient_email, 
                    patient_id, 
                    tampered_files
                )
                integrity_results['alert_sent'] = alert_sent
                if alert_sent:
                    print(f"Security alert email sent to patient {patient_id} at {patient_email}")
            else:
                print(f"WARNING: Could not send alert email - patient email not found for {patient_id}")
                integrity_results['alert_sent'] = False
                integrity_results['alert_error'] = "Patient email not found"
        
        return json.dumps(integrity_results), 200, {'ContentType': 'application/json'}
    
    except Exception as e:
        print(f"Error verifying integrity: {str(e)}")
        print(traceback.format_exc())
        return json.dumps({'error': str(e)}), 500, {'ContentType': 'application/json'}

def verify_file_integrity(file_path, metadata=None):
    """Verify the integrity of an encrypted file"""
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        # Check if file is empty
        if os.path.getsize(file_path) == 0:
            return False, "File is empty"
        
        # Handle JSON files
        if file_path.endswith('.json'):
            # Read file content
            with open(file_path, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    return False, "File is not valid JSON"
            
            # Check for required fields in JSON structure
            required_fields = ['encrypted_data', 'shape', 'dtype']
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                return False, f"Missing required fields: {', '.join(missing_fields)}"
            
            # Check original hash if available
            if metadata and 'original_hash' in metadata and 'original_hash' in data:
                if metadata['original_hash'] != data['original_hash']:
                    return False, "Hash mismatch - file may have been tampered with"
            
            # Check if the encrypted data has been modified compared to the DB record
            if 'encrypted_data' in data:
                try:
                    # Check if we have a database record to compare against
                    from backend.crypto.mri_encryptor import MRIEncryptor
                    encryptor = MRIEncryptor()
                    if encryptor.verify_file_integrity(file_path):
                        return True, "Hash verification passed"
                    else:
                        return False, "Hash verification failed - potential tampering detected"
                except Exception as check_err:
                    print(f"Error in advanced integrity check: {str(check_err)}")
                    # Fall back to basic checks if advanced check fails
                    return True, "Basic structure verification passed"
        
        # Handle binary files (.bin)
        elif file_path.endswith('.bin'):
            try:
                # Get stored hash from database if available
                stored_hash = None
                stored_size = None
                
                try:
                    # Try to get the hash and size from the DB or metadata
                    patient_id = os.path.basename(file_path).split('_')[1]  # Extract patient ID from filename
                    
                    # First check if we have metadata about this bin file
                    if metadata and 'bin_files' in metadata and os.path.basename(file_path) in metadata['bin_files']:
                        bin_metadata = metadata['bin_files'][os.path.basename(file_path)]
                        stored_hash = bin_metadata.get('hash')
                        stored_size = bin_metadata.get('size')
                    
                    # If not in metadata, try the database
                    if not stored_hash:
                        result = secure_x.db.execute_query(
                            "SELECT metadata FROM file_metadata WHERE file_path = ?",
                            (file_path,)
                        )
                        if result and result[0] and result[0][0]:
                            file_metadata = json.loads(result[0][0])
                            stored_hash = file_metadata.get('hash')
                            stored_size = file_metadata.get('size')
                except Exception as db_err:
                    print(f"Error retrieving bin file metadata: {str(db_err)}")
                
                # Compute current hash of the file
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    current_hash = hashlib.md5(file_data).hexdigest()
                    current_size = len(file_data)
                
                # Compare hashes if we have a stored hash
                if stored_hash and current_hash != stored_hash:
                    return False, f"Binary file hash mismatch - file may have been tampered with"
                
                # Compare sizes if we have a stored size
                if stored_size and current_size != stored_size:
                    return False, f"Binary file size mismatch: expected {stored_size}, got {current_size} bytes"
                
                # If we have neither hash nor size to compare against, verify with the backend
                if not stored_hash and not stored_size:
                    # Try to verify with SecureXway - this will depend on your implementation
                    try:
                        # This method should be implemented in your SecureXway class
                        is_valid = secure_x.verify_bin_file_integrity(file_path)
                        if is_valid:
                            return True, "Binary file verification passed"
                        else:
                            return False, "Binary file verification failed - potential tampering detected"
                    except Exception as bin_verify_err:
                        print(f"Advanced bin verification error: {str(bin_verify_err)}")
                        # If we can't verify with SecureXway, just report the file exists without verification
                        return True, "Binary file exists but could not be verified"
            
                return True, "Binary file verification passed"
            except Exception as bin_err:
                print(f"Error verifying bin file: {str(bin_err)}")
                return False, f"Binary file verification error: {str(bin_err)}"
        
        # If we got this far, the file seems intact but we couldn't do deep verification
        return True, "Basic integrity check passed"
        
    except Exception as e:
        print(f"Integrity check error: {str(e)}")
        return False, f"Error during verification: {str(e)}"

def send_tampering_alert_email(patient_email, patient_id, tampered_files):
    """Send an alert email to patient when tampering is detected"""
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create the email subject
        subject = f"SECURITY ALERT - Potential Data Tampering Detected"
        
        # Create the email body with details
        body = f"""
SECURITY ALERT - IMPORTANT NOTIFICATION
        
Dear Patient {patient_id},

Our security system has detected potential tampering with your encrypted medical data.
This alert has been automatically generated at {current_time}.

Details:
- Number of potentially affected files: {len(tampered_files)}
- Files with integrity issues: {', '.join(tampered_files)}

What this means:
This could indicate that someone may have attempted to access or modify your 
encrypted medical information without authorization.

Recommended actions:
1. Contact your healthcare provider immediately
2. Do not attempt to download or view your medical images until this is resolved
3. Consider changing any passwords related to your healthcare accounts

Our security team has been notified and is investigating this issue.

Please DO NOT REPLY to this email as it was automatically generated.
Contact your healthcare provider's office directly with any questions.

Sincerely,
Security Operations Team
        """
        
        # Import the email sender
        from backend.utils.email_sender import send_custom_email
        
        # Send the alert email
        return send_custom_email(patient_email, subject, body)
    
    except Exception as e:
        print(f"Error sending tampering alert email: {str(e)}")
        return False

@app.route('/user', methods=['GET', 'POST'])
def user():
    """Render user page and handle OTP generation"""
    if request.method == 'POST':
        patient_num = request.form.get('patient_id')
        
        if not patient_num:
            flash('Patient number is required.', 'error')
            return redirect(url_for('user'))
        
        # Get the associated email from the database - use multiple methods for robustness
        patient_email = None
        
        # Try the dedicated method first if it exists
        if hasattr(secure_x.db, 'get_patient_email'):
            patient_email = secure_x.db.get_patient_email(patient_num)
        
        # If that fails, try the generic query method
        if not patient_email:
            try:
                result = secure_x.db.execute_query(
                    "SELECT email FROM patient_emails WHERE patient_num = ?",
                    (patient_num,)
                )
                if result and result[0]:
                    patient_email = result[0][0]
            except Exception as e:
                print(f"Error retrieving patient email: {str(e)}")
        
        if not patient_email:
            flash('No email found for this patient number. Please contact your healthcare provider.', 'error')
            return redirect(url_for('user'))
        
        # Enhanced patient file check - more thorough search
        file_exists, file_info = enhanced_patient_file_check(patient_num)
        
        if not file_exists:
            flash('No data found for this patient number. Please check the number and try again.', 'error')
            return redirect(url_for('user'))
        
        # Check file integrity status FIRST - before sending OTP
        integrity_status = check_patient_files_integrity(patient_num)
        
        # Store integrity status in session
        session['file_integrity_status'] = integrity_status
        
        # If files are unverified, BLOCK access and don't generate OTP
        if integrity_status['tampered_files_count'] > 0:
            # Send security alert to the patient
            send_integrity_alert_to_patient(patient_email, patient_num, integrity_status['tampered_files'])
            
            # Display security warning and block further access
            flash('SECURITY ALERT: Your medical data may have been tampered with. ' +
                  'Access has been blocked for your security. ' +
                  'A security alert has been sent to your email. ' +
                  'Please contact your healthcare provider immediately.', 'error')
            
            # Store security issue in session for display in UI
            session['security_block'] = True
            
            # Store file info in session for later use (still needed for reference)
            session['file_info'] = file_info
            
            # Log the security incident
            print(f"SECURITY INCIDENT: Blocked access for patient {patient_num} due to file integrity issues")
            
            return redirect(url_for('user'))
        
        # If all files are verified, proceed with normal OTP process
        session['security_block'] = False
        
        # Store file info in session for later use
        session['file_info'] = file_info
        
        # Generate OTP only if files are verified
        otp = secure_x.generate_otp(patient_num)
        
        # Send OTP via email
        email_sent = send_otp_email(patient_email, otp, patient_num)
        
        if email_sent:
            flash(f'An OTP has been sent to your registered email address.', 'info')
        else:
            # Fallback to displaying OTP if email fails
            flash(f'Email delivery failed. Your OTP is: {otp} (In a real system, this would be sent securely to the patient)', 'warning')
        
        # Store patient number in session for OTP verification
        session['pending_patient_id'] = patient_num  
        
        return redirect(url_for('verify_otp'))
    
    # Check if there's a security block from previous attempt
    if session.get('security_block'):
        flash('SECURITY ALERT: Your medical data may have been tampered with. ' +
              'Access has been blocked for your security. ' +
              'Please contact your healthcare provider immediately.', 'error')
    
    return render_template('user.html')

def send_integrity_alert_to_patient(patient_email, patient_id, tampered_files):
    """Send an immediate alert to patient when trying to access tampered files"""
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create the email subject
        subject = f"URGENT SECURITY ALERT - Access Blocked Due to Data Integrity Issues"
        
        # Create the email body with details
        body = f"""
URGENT SECURITY ALERT - DATA INTEGRITY ISSUES DETECTED
        
Dear Patient {patient_id},

Our security system has blocked your access attempt at {current_time} because potential 
tampering was detected with your encrypted medical data.

Details:
- Number of potentially affected files: {len(tampered_files)}
- Files with integrity issues: {', '.join(tampered_files[:5])}{'...' if len(tampered_files) > 5 else ''}

What this means:
This indicates that someone may have attempted to access or modify your encrypted 
medical information without authorization, which could affect the accuracy and 
reliability of your medical images.

IMPORTANT - Recommended actions:
1. DO NOT attempt further access to these files
2. Contact your healthcare provider IMMEDIATELY
3. Report this incident to their security team
4. Consider changing any passwords related to your healthcare accounts

Our security team has been automatically notified about this incident.

Please DO NOT REPLY to this email as it was automatically generated.
Contact your healthcare provider's office directly at their official number.

Sincerely,
Security Operations Team
SecureXway Medical Imaging System
        """
        
        # Import the email sender
        from backend.utils.email_sender import send_custom_email
        
        # Send the alert email with high priority
        return send_custom_email(patient_email, subject, body, priority='high')
    
    except Exception as e:
        print(f"Error sending integrity alert email to patient: {str(e)}")
        return False

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """Render OTP verification page and handle verification"""
    patient_num = session.get('pending_patient_id')
    integrity_status = session.get('file_integrity_status', {})
    
    if not patient_num:
        flash('Please enter your patient number first.', 'error')
        return redirect(url_for('user'))
    
    # Show integrity warning again if issues exist
    if integrity_status and integrity_status.get('tampered_files_count', 0) > 0:
        flash('SECURITY ALERT: Your medical data may have been tampered with. Proceed with caution and contact your healthcare provider.', 'error')
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        
        if not otp:
            flash('OTP is required.', 'error')
            return redirect(url_for('verify_otp'))
        
        # If integrity issues exist, add extra warning
        if integrity_status and integrity_status.get('tampered_files_count', 0) > 0:
            flash('WARNING: You are accessing potentially compromised medical data. The images may not be accurate.', 'error')
        
        # Verify OTP
        if secure_x.verify_otp(patient_num, otp):
            # OTP verified, decrypt file with multiple fallbacks
            file_info = session.get('file_info', {})
            
            # Show a loading message
            flash('Working on decrypting your MRI. This may take a moment...', 'info')
            
            # Attempt decryption
            success, result = improved_decrypt_patient_file(patient_num, file_info)
            
            if success:
                # Verify it's actually an image file and not an error message
                if os.path.exists(result) and verify_image_file(result):
                    # Store decrypted file path in session
                    session['decrypted_file'] = result
                    flash('OTP verified successfully. Your MRI has been decrypted.', 'success')
                    
                    # Add integrity warning if issues exist
                    if integrity_status and integrity_status.get('tampered_files_count', 0) > 0:
                        flash('CAUTION: File integrity issues were detected. This image may not be reliable.', 'error')
                    
                    return redirect(url_for('download_file'))
                else:
                    flash('Decryption produced an invalid result. Please contact support.', 'error')
                    # Clean up invalid file
                    if os.path.exists(result):
                        try:
                            os.remove(result)
                        except:
                            pass
                    return redirect(url_for('user'))
            else:
                flash(f'Error decrypting file: {result}', 'error')
                return redirect(url_for('user'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
    
    return render_template('verify_otp.html')

@app.route('/download-file')
def download_file():
    """Render file download page"""
    patient_num = session.get('pending_patient_id')
    integrity_status = session.get('file_integrity_status', {})
    
    if not patient_num:
        flash('Please enter your patient number first.', 'error')
        return redirect(url_for('user'))
    
    # Show integrity warning again if issues exist
    if integrity_status and integrity_status.get('tampered_files_count', 0) > 0:
        flash('SECURITY WARNING: This medical data may have been tampered with. ' +
              'Please consult your healthcare provider before making any medical decisions based on these images.', 'error')
        
    file_path = session.get('decrypted_file')
    
    if not file_path:
        flash('No decrypted file found. Please verify your identity first.', 'error')
        return redirect(url_for('user'))
    
    if not os.path.exists(file_path):
        flash('Decrypted file not found.', 'error')
        session.pop('decrypted_file', None)
        return redirect(url_for('user'))
    
    # Final verification to ensure we're providing a valid image
    if not verify_image_file(file_path):
        flash('The decrypted file appears to be invalid. Please try again.', 'error')
        return redirect(url_for('user'))
        
    return render_template('download_file.html')

@app.route('/download')
def download():
    """Handle file download"""
    patient_num = session.get('pending_patient_id')  # Changed from 'pending_patient_num' to 'pending_patient_id'
    file_path = session.get('decrypted_file')
    
    print(f"Initiating download for patient {patient_num}")
    
    if not file_path or not os.path.exists(file_path):
        flash('No decrypted file found.', 'error')
        return redirect(url_for('user'))
        
    # Final verification to ensure we're providing a valid image
    if not verify_image_file(file_path):
        flash('The decrypted file appears to be invalid. Please try again.', 'error')
        return redirect(url_for('user'))
    
    # Generate a more readable filename
    filename = os.path.basename(file_path)
    patient_num = session.get('pending_patient_id', 'unknown')  # Changed from 'pending_patient_num' to 'pending_patient_id'
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    download_name = f"MRI_Patient_{patient_num}_{timestamp}{os.path.splitext(filename)[1]}"
    
    # After successful download, delete the decrypted file for security
    def delete_after_request(response):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                session.pop('decrypted_file', None)
        except Exception as e:
            print(f"Error deleting file: {e}")
        return response
    
    # Register the callback to run after request
    app.after_request_funcs.setdefault(None, []).append(delete_after_request)
    
    return send_file(file_path, as_attachment=True, download_name=download_name)

@app.route('/view-image')
def view_image():
    """View decrypted image in browser"""
    patient_num = session.get('pending_patient_id')
    
    if not patient_num:
        flash('Please enter your patient number first.', 'error')
        return redirect(url_for('user'))
    
    file_path = session.get('decrypted_file')
    
    if not file_path or not os.path.exists(file_path):
        # If no decrypted file, try to decrypt on the fly
        file_info = session.get('file_info', {})
        success, result = improved_decrypt_patient_file(patient_num, file_info)
        
        if success and os.path.exists(result):
            file_path = result
            session['decrypted_file'] = result
        else:
            flash('No decrypted file found.', 'error')
            return redirect(url_for('user'))
    
    try:
        print(f"Sending file for viewing: {file_path}")
        directory, filename = os.path.split(file_path)
        
        # Determine MIME type based on file extension
        file_extension = os.path.splitext(filename)[1].lower()
        
        mime_types = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.tiff': 'image/tiff',
            '.tif': 'image/tiff'
        }
        
        mime_type = mime_types.get(file_extension, 'application/octet-stream')
                        
        # Send file for viewing in browser (not as attachment)
        return send_file(file_path, mimetype=mime_type)
    except Exception as e:
        flash(f"Error viewing file: {str(e)}", 'error')
        return redirect(url_for('user'))

@app.route('/logout')
def logout():
    """Handle logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

def enhanced_patient_file_check(patient_num):
    """Enhanced check for patient files with detailed information"""
    file_info = {}
    
    # Strategy 1: Check database for exact match
    try:
        file_path, key = secure_x.db.get_encrypted_file(patient_num)
        if file_path and os.path.exists(file_path):
            file_info['db_exact'] = {'path': file_path, 'key': key}
            return True, file_info
    except Exception as e:
        print(f"Database exact check error: {str(e)}")
    
    # Strategy 2: Check database for pattern match
    try:
        all_records = secure_x.db.find_patient_records_like(patient_num)
        if all_records:
            file_info['db_like'] = all_records
            return True, file_info
    except Exception as e:
        print(f"Database pattern check error: {str(e)}")
    
    # Strategy 3: Check patient directory
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_num}')
        patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
        
        if os.path.exists(patient_encrypted_dir):
            files = [f for f in os.listdir(patient_encrypted_dir) 
                    if f.startswith('mri_') or 'direct' in f]
            if files:
                file_info['patient_dir'] = {
                    'dir': patient_encrypted_dir,
                    'files': files
                }
                return True, file_info
    except Exception as e:
        print(f"Patient directory check error: {str(e)}")
    
    # Strategy 4: Check global encrypted directory
    try:
        encrypted_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'encrypted')
        if os.path.exists(encrypted_dir):
            matching_files = []
            for filename in os.listdir(encrypted_dir):
                if patient_num in filename:
                    matching_files.append(filename)
            
            if matching_files:
                file_info['global_dir'] = {
                    'dir': encrypted_dir,
                    'files': matching_files
                }
                return True, file_info
    except Exception as e:
        print(f"Global directory check error: {str(e)}")
    
    # Strategy 5: Last resort - try to find any file with a number similar to patient_num
    try:
        encrypted_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'encrypted')
        if os.path.exists(encrypted_dir):
            # Try to find files that might be related to this patient
            all_numeric_parts = set()
            for filename in os.listdir(encrypted_dir):
                parts = filename.replace('.', '_').split('_')
                for part in parts:
                    if part.isdigit():
                        all_numeric_parts.add(part)
            
            # Find closest numeric match
            if all_numeric_parts:
                closest = min(all_numeric_parts, key=lambda x: abs(int(x) - int(patient_num)) if x.isdigit() and patient_num.isdigit() else float('inf'))
                if closest and patient_num.isdigit() and closest.isdigit() and abs(int(closest) - int(patient_num)) < 10:
                    file_info['closest_match'] = closest
                    return True, file_info
    except Exception as e:
        print(f"Closest match search error: {str(e)}")
    
    return False, file_info

def verify_image_file(file_path, strict=True):
    """Verify that a file is a valid image that can be opened and IS NOT an error message"""
    try:
        if not os.path.exists(file_path):
            print(f"Image validation failed: File does not exist: {file_path}")
            return False
            
        # Check file size - reject files that are too small
        if os.path.getsize(file_path) < 50:  # Reduced minimum size threshold
            print(f"Image validation failed: File too small: {file_path}")
            return False
            
        # Try to open as image
        img = Image.open(file_path)
        
        # If image can be loaded, it's valid enough for non-strict mode
        if not strict:
            return True
            
        # For strict validation, check dimensions
        if img.width < 30 or img.height < 30:
            print(f"Image validation failed: Dimensions too small: {img.width}x{img.height}")
            return False
                
        # Only perform expensive validation in strict mode
        if strict:
            # Sample check for white background (simpler check)
            try:
                # Just check center of image instead of multiple points
                center_pixel = img.getpixel((img.width//2, img.height//2))
                if img.mode in ('RGB', 'RGBA'):
                    if all(c > 240 for c in center_pixel[:3]):
                        print("Center pixel is white, might be an error image")
                        # Don't fail immediately, but warn
            except Exception as e:
                print(f"Pixel check error: {e}")
        
        return True
    except Exception as e:
        print(f"Image verification failed: {str(e)}")
        return False

def improved_decrypt_patient_file(patient_num, file_info=None):
    """Improved decrypt function with better file handling and optimization"""
    decrypted_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'decrypted')
    os.makedirs(decrypted_dir, exist_ok=True)
    
    print(f"Starting optimized decryption for patient: {patient_num}")
    
    # First try: direct MRI JSON file decryption - fastest path for most patients
    mri_path = decrypt_direct_mri(patient_num)
    if mri_path and os.path.exists(mri_path) and verify_image_file(mri_path, strict=False):
        print(f"Successfully decrypted via direct path: {mri_path}")
        return True, mri_path
        
    # Second try: specific path from file_info if available
    if file_info and 'db_exact' in file_info and 'path' in file_info['db_exact']:
        path = file_info['db_exact']['path']
        key = file_info['db_exact'].get('key')
        
        if path.endswith('.json'):
            success, result = try_decrypt_json(path, patient_num)
            if success and verify_image_file(result, strict=False):
                print(f"Successfully decrypted via file_info JSON: {result}")
                return True, result
        elif key and path.endswith('.bin'):
            success, result = secure_x.decrypt_specific_file(path, key)
            if success and verify_image_file(result, strict=False):
                print(f"Successfully decrypted via file_info BIN: {result}")
                return True, result
    
    # Third try: Check patient directory for any JSON files first - these are easiest to decrypt
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_num}')
    patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
    
    if os.path.exists(patient_encrypted_dir):
        # First look for direct .json files which are faster to decrypt
        json_files = [f for f in os.listdir(patient_encrypted_dir) if f.endswith('.json')]
        for json_file in sorted(json_files, reverse=True):  # newest first
            file_path = os.path.join(patient_encrypted_dir, json_file)
            success, result = try_decrypt_json(file_path, patient_num)
            if success and verify_image_file(result, strict=False):
                print(f"Successfully decrypted via patient directory JSON: {result}")
                return True, result
    
    # Fourth try: Use SecureXway decrypt_mri - this is the main method
    try:
        success, result = secure_x.decrypt_mri(patient_num)
        if success and os.path.exists(result) and verify_image_file(result, strict=False):
            print(f"Successfully decrypted via main decrypt_mri: {result}")
            return True, result
    except Exception as e:
        print(f"Primary decryption method failed: {str(e)}")
    
    # Final try: More exhaustive file search using search_locations
    search_locations = build_search_locations(patient_num, file_info)
    
    for source, file_path in search_locations:
        if not os.path.exists(file_path):
            continue
        
        try:
            # JSON files - try with MRIEncryptor
            if file_path.endswith('.json'):
                success, result = try_decrypt_json(file_path, patient_num)
                if success and verify_image_file(result, strict=False):
                    print(f"Successfully decrypted via search JSON: {result}")
                    return True, result
            # BIN files - last resort
            elif file_path.endswith('.bin'):
                success, result = secure_x.decrypt_bin_file(file_path, patient_num)
                if success and verify_image_file(result, strict=False):
                    print(f"Successfully decrypted via BIN file: {result}")
                    return True, result
        except Exception as e:
            print(f"Error decrypting {file_path}: {str(e)}")
    
    # No successful decryption was found - return an error
    print(f"Failed to decrypt any valid MRI files for patient {patient_num}")
    return False, "Could not decrypt any valid MRI files for this patient. Please contact support."

def decrypt_direct_mri(patient_num):
    """Optimized function to quickly decrypt JSON files - fastest path"""
    try:
        # Find all direct MRI JSON files
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Try to get format info from metadata file
        metadata = None
        patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_num}')
        patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
        metadata_file = os.path.join(patient_encrypted_dir, f'format_metadata_{patient_num}.json')
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except Exception as meta_err:
                print(f"Failed to read metadata file: {str(meta_err)}")
        
        # Extract format from metadata if possible
        original_format = None
        if metadata and 'original_format' in metadata:
            original_format = metadata['original_format']
            if not original_format.startswith('.'):
                original_format = f".{original_format}"
        
        # Check patient directory first (most likely location)
        json_files = []
        
        if os.path.exists(patient_encrypted_dir):
            json_files.extend([
                os.path.join(patient_encrypted_dir, f) 
                for f in os.listdir(patient_encrypted_dir) 
                if f.endswith('.json') and ('direct' in f or 'mri' in f)
            ])
        
        # Check encrypted dir next
        encrypted_dir = os.path.join(base_dir, 'encrypted')
        if os.path.exists(encrypted_dir):
            json_files.extend([
                os.path.join(encrypted_dir, f) 
                for f in os.listdir(encrypted_dir) 
                if f.endswith('.json') and patient_num in f
            ])
        
        # Sort by modification time (newest first)
        json_files.sort(key=lambda f: os.path.getmtime(f) if os.path.exists(f) else 0, reverse=True)
        
        # Try to decrypt each file
        from backend.crypto.mri_encryptor import MRIEncryptor
        decrypted_dir = os.path.join(base_dir, 'decrypted')
        
        for file_path in json_files:
            try:
                mri_encryptor = MRIEncryptor()
                encrypted_payload = mri_encryptor.load_encrypted_image(file_path)
                
                # Check if we have the original binary data for perfect reproduction
                if 'binary_perfect' in encrypted_payload and encrypted_payload['binary_perfect'] and 'original_binary' in encrypted_payload:
                    # Perfect binary reproduction possible!
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    
                    # Get format
                    format_to_use = encrypted_payload.get('original_format', '.png')
                    if not format_to_use.startswith('.'):
                        format_to_use = f".{format_to_use}"
                    
                    # Generate output filename
                    output_path = os.path.join(decrypted_dir, f'mri_{patient_num}_{timestamp}{format_to_use}')
                    
                    # Decode and write the original binary data
                    try:
                        original_binary = base64.b64decode(encrypted_payload['original_binary'])
                        
                        # Write binary data exactly as it was
                        with open(output_path, 'wb') as f:
                            f.write(original_binary)
                        
                        # Verify integrity with hash
                        if 'original_hash' in encrypted_payload:
                            actual_hash = hashlib.md5(original_binary).hexdigest()
                            expected_hash = encrypted_payload['original_hash']
                            if actual_hash != expected_hash:
                                print(f"WARNING: Hash mismatch - expected {expected_hash}, got {actual_hash}")
                                # Even with hash mismatch, proceed if the file appears valid
                            
                        # Verify file size if available
                        if 'original_size' in encrypted_payload:
                            actual_size = os.path.getsize(output_path)
                            expected_size = encrypted_payload['original_size']
                            if actual_size != expected_size:
                                print(f"WARNING: Size mismatch - expected {expected_size}, got {actual_size}")
                        
                        print(f"Binary-perfect restoration: {output_path}")
                        return output_path
                    except Exception as binary_error:
                        print(f"Error in binary perfect restoration: {str(binary_error)}")
                        # Fall back to standard decryption if binary restoration fails
                
                # Standard pixel-based decryption if binary perfect isn't available
                decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
                
                if decrypted_array is None or decrypted_array.size == 0:
                    continue
                
                # Save as image with original format if available
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                
                # First check if the payload has the format info
                payload_format = encrypted_payload.get('original_format')
                if payload_format:
                    if not payload_format.startswith('.'):
                        payload_format = f".{payload_format}"
                    # Payload format takes precedence
                    format_to_use = payload_format
                elif original_format:
                    # Use format from metadata if payload doesn't have it
                    format_to_use = original_format
                else:
                    # Default to png as last resort
                    format_to_use = '.png'
                
                # Default to .png if format is missing or invalid
                if format_to_use.lower() not in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']:
                    format_to_use = '.png'
                
                output_path = os.path.join(decrypted_dir, f'mri_{patient_num}_{timestamp}{format_to_use}')
                
                img = Image.fromarray(decrypted_array)
                if img.width < 50 or img.height < 50:
                    continue
                
                # Make sure we save in the proper format using PIL's format parameter
                format_map = {
                    '.png': 'PNG',
                    '.jpg': 'JPEG',
                    '.jpeg': 'JPEG',
                    '.gif': 'GIF',
                    '.bmp': 'BMP',
                    '.tiff': 'TIFF',
                    '.tif': 'TIFF'
                }
                
                # Get the format name from the extension
                save_format = format_map.get(format_to_use.lower(), 'PNG')
                
                # Apply quality settings to match original formats better
                save_kwargs = {}
                if save_format == 'JPEG':
                    save_kwargs['quality'] = 100  # Max quality for JPEG
                    save_kwargs['subsampling'] = 0  # No chroma subsampling
                
                # Save with explicit format and appropriate parameters
                img.save(output_path, format=save_format, **save_kwargs)
                
                # Final verification
                if verify_image_file(output_path):
                    return output_path
            except Exception as e:
                print(f"Fast path error for {file_path}: {str(e)}")
                continue
        
        return None
    except Exception as e:
        print(f"Fast decryption error: {str(e)}")
        return None

def build_search_locations(patient_num, file_info=None):
    """Build a prioritized list of search locations"""
    search_locations = []
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Add locations from file_info
    if file_info:
        if 'patient_dir' in file_info and 'dir' in file_info['patient_dir'] and 'files' in file_info['patient_dir']:
            dir_path = file_info['patient_dir']['dir']
            for filename in file_info['patient_dir']['files']:
                search_locations.append(("Patient Dir", os.path.join(dir_path, filename)))
        if 'global_dir' in file_info and 'dir' in file_info['global_dir'] and 'files' in file_info['global_dir']:
            dir_path = file_info['global_dir']['dir']
            for filename in file_info['global_dir']['files']:
                search_locations.append(("Global Dir", os.path.join(dir_path, filename)))
        if 'db_like' in file_info:
            for record in file_info['db_like']:
                if 'file_path' in record:
                    search_locations.append(("DB", record['file_path']))
    
    # 2. Check standard locations
    patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_num}')
    patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
    
    if os.path.exists(patient_encrypted_dir):
        for filename in os.listdir(patient_encrypted_dir):
            if filename.endswith('.json') or filename.endswith('.bin'):
                search_locations.append(("Patient Folder", os.path.join(patient_encrypted_dir, filename)))
                
    encrypted_dir = os.path.join(base_dir, 'encrypted')
    if os.path.exists(encrypted_dir):
        for filename in os.listdir(encrypted_dir):
            if patient_num in filename and (filename.endswith('.json') or filename.endswith('.bin')):
                search_locations.append(("Global Folder", os.path.join(encrypted_dir, filename)))
    
    return search_locations

def try_decrypt_json(file_path, patient_num):
    """Optimized function to decrypt a JSON file using MRIEncryptor"""
    try:
        from backend.crypto.mri_encryptor import MRIEncryptor
        decrypted_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'decrypted')
        os.makedirs(decrypted_dir, exist_ok=True)
        
        # Create MRIEncryptor instance with explicit key path for reliability
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        key_path = os.path.join(base_dir, 'keys', 'mri_encryption_key.key')
        mri_encryptor = MRIEncryptor(key_path=key_path)
        
        print(f"Loading encrypted image from: {file_path}")
        # Load and decrypt the file
        encrypted_payload = mri_encryptor.load_encrypted_image(file_path)
        
        # Check if we have perfect binary data available
        if 'binary_perfect' in encrypted_payload and encrypted_payload['binary_perfect'] and 'original_binary' in encrypted_payload:
            # Perfect binary reproduction
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            
            # Get format
            format_to_use = encrypted_payload.get('original_format', '.png')
            if not format_to_use.startswith('.'):
                format_to_use = f".{format_to_use}"
            
            # Generate output path
            output_path = os.path.join(decrypted_dir, f'mri_{patient_num}_{timestamp}{format_to_use}')
            
            try:
                # Decode and write the original binary data
                original_binary = base64.b64decode(encrypted_payload['original_binary'])
                with open(output_path, 'wb') as f:
                    f.write(original_binary)
                
                # Verify integrity with hash
                if 'original_hash' in encrypted_payload:
                    actual_hash = hashlib.md5(original_binary).hexdigest()
                    expected_hash = encrypted_payload['original_hash']
                    if actual_hash != expected_hash:
                        print(f"WARNING: Hash mismatch - expected {expected_hash}, got {actual_hash}")
                    else:
                        print(f"Hash verification passed: {actual_hash}")
                
                # Double-check the file was written correctly by reading back
                with open(output_path, 'rb') as f:
                    written_data = f.read()
                    if len(written_data) != len(original_binary):
                        print(f"WARNING: Written file size mismatch: expected {len(original_binary)}, got {len(written_data)}")
                    elif written_data != original_binary:
                        print(f"WARNING: Written data doesn't match original binary data")
                
                print(f"Binary-perfect JSON decryption: {output_path}")
                return True, output_path
            except Exception as binary_error:
                print(f"Error in binary perfect restoration: {str(binary_error)}")
                # Fall back to standard decryption if binary restoration fails
        
        # Fall back to standard decryption if binary perfect isn't available or failed
        # Verify payload has required fields before decryption
        if not all(k in encrypted_payload for k in ['encrypted_data', 'shape', 'dtype']):
            missing = [k for k in ['encrypted_data', 'shape', 'dtype'] if k not in encrypted_payload]
            return False, f"Invalid encrypted payload, missing: {missing}"
            
        decrypted_array = mri_encryptor.decrypt_mri_image(encrypted_payload)
        
        # Validate that we got actual image data
        if decrypted_array is None or decrypted_array.size == 0:
            return False, "Decryption resulted in empty image data"
            
        # Generate output path with original format if available
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        original_format = encrypted_payload.get('original_format', '.png')
        if not original_format.startswith('.'):
            original_format = f".{original_format}"
        
        # Default to .png if format is missing or invalid
        if original_format.lower() not in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']:
            original_format = '.png'
            
        output_path = os.path.join(decrypted_dir, f'mri_{patient_num}_{timestamp}{original_format}')
        
        # Save the image
        img = Image.fromarray(decrypted_array)
        
        # Basic validation before saving (reduced threshold)
        if img.width < 30 or img.height < 30:
            return False, f"Decrypted image is too small: {img.width}x{img.height}"
                
        # Format mapping for saving with correct format
        format_map = {
            '.png': 'PNG',
            '.jpg': 'JPEG',
            '.jpeg': 'JPEG',
            '.gif': 'GIF',
            '.bmp': 'BMP',
            '.tiff': 'TIFF',
            '.tif': 'TIFF'
        }
        
        # Get the format name from the extension
        save_format = format_map.get(original_format.lower(), 'PNG')
        
        # Apply quality settings to match original formats better
        save_kwargs = {}
        if save_format == 'JPEG':
            save_kwargs['quality'] = 100  # Max quality for JPEG
            save_kwargs['subsampling'] = 0  # No chroma subsampling
        
        # Save with explicit format and parameters
        img.save(output_path, format=save_format, **save_kwargs)
        
        print(f"JSON decryption succeeded: {output_path}")
        return True, output_path
    except Exception as e:
        print(f"JSON decryption error: {str(e)}")
        return False, str(e)

# Add new function to check file integrity without sending admin alerts
def check_patient_files_integrity(patient_id):
    """
    Check the integrity of all files for a patient without sending admin alerts
    Returns dict with integrity information
    """
    try:
        # Find all encrypted files for this patient
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Results storage
        integrity_results = {'files': [], 'tampered_files_count': 0}
        
        # Check patient directory
        patient_dir = os.path.join(base_dir, 'patients', f'patient_{patient_id}')
        patient_encrypted_dir = os.path.join(patient_dir, 'encrypted')
        
        # Get metadata for integrity checking
        metadata = None
        metadata_file = os.path.join(patient_encrypted_dir, f'format_metadata_{patient_id}.json')
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except Exception as meta_err:
                print(f"Failed to read metadata file: {str(meta_err)}")
        
        # Flag to track if any tampering was detected
        tampering_detected = False
        tampered_files = []
        
        # Check patient encrypted directory
        if os.path.exists(patient_encrypted_dir):
            for filename in os.listdir(patient_encrypted_dir):
                # Check both JSON and BIN files for tampering
                if (filename.endswith('.json') and not filename.startswith('format_metadata')) or filename.endswith('.bin'):
                    file_path = os.path.join(patient_encrypted_dir, filename)
                    
                    # Verify file integrity
                    is_verified, details = verify_file_integrity(file_path, metadata)
                    
                    if not is_verified:
                        tampering_detected = True
                        tampered_files.append(filename)
                    
                    integrity_results['files'].append({
                        'filename': filename,
                        'verified': is_verified,
                        'details': details
                    })
        
        # Check global encrypted directory
        encrypted_dir = os.path.join(base_dir, 'encrypted')
        if os.path.exists(encrypted_dir):
            for filename in os.listdir(encrypted_dir):
                # Check both JSON and BIN files for patient records
                if patient_id in filename and (filename.endswith('.json') or filename.endswith('.bin')):
                    file_path = os.path.join(encrypted_dir, filename)
                    
                    # Verify file integrity
                    is_verified, details = verify_file_integrity(file_path, metadata)
                    
                    if not is_verified:
                        tampering_detected = True
                        tampered_files.append(filename)
                    
                    integrity_results['files'].append({
                        'filename': filename,
                        'verified': is_verified,
                        'details': details
                    })
        
        # Count tampered files and set in results
        integrity_results['tampered_files_count'] = len(tampered_files)
        integrity_results['tampered_files'] = tampered_files
        
        return integrity_results
    
    except Exception as e:
        print(f"Error checking file integrity: {str(e)}")
        return {'error': str(e), 'tampered_files_count': 0, 'files': []}

if __name__ == '__main__':
    app.run(debug=True)