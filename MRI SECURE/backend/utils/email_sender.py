import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_otp_email(recipient_email, otp, patient_num):
    """
    Sends an OTP code to a patient's email
    
    Parameters:
    -----------
    recipient_email : str
        Email address of the recipient
    otp : str
        The OTP code to be sent
    patient_num : str
        Patient number for reference
    
    Returns:
    --------
    bool
        True if email was sent successfully, False otherwise
    """
    # Fixed sender credentials
    sender_email = ''
    sender_password = ''
    
    try:
        # Create a multipart message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"Secure MRI Access Code - Patient {patient_num}"
        
        # Email body with OTP
        body = f"""Dear Patient,

Your one-time password (OTP) for accessing your MRI records is:

{otp}

This code will expire after use. Please do not share it with anyone.

If you did not request this code, please contact your healthcare provider immediately.

Regards,
Secure MRI Access System
"""
        
        # Add timestamp to the message
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"{body}\n\nSent at: {timestamp}"
        
        # Attach the message to the email
        msg.attach(MIMEText(full_message, 'plain'))
        
        # Set up the SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Secure the connection
        
        # Login with sender credentials
        try:
            server.login(sender_email, sender_password)
        except smtplib.SMTPAuthenticationError:
            logger.error("Authentication failed. Check the app password.")
            return False
        
        # Send the email
        server.send_message(msg)
        
        # Close the connection
        server.quit()
        
        logger.info(f"OTP email sent successfully to {recipient_email}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to send OTP email. Error: {str(e)}")
        return False

def send_custom_email(recipient_email, subject, body, priority=None):
    """
    Send a custom email with the given subject and body to the recipient.
    
    Args:
        recipient_email (str): The recipient's email address
        subject (str): The email subject line
        body (str): The email body text
        priority (str, optional): Email priority ('high', 'normal', 'low')
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    sender_email = ''
    sender_password = ''
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587

    try:
        # Create message container
        message = MIMEMultipart()
        message['Subject'] = subject
        message['From'] = sender_email
        message['To'] = recipient_email
        
        # Add priority headers if specified
        if priority == 'high':
            message['X-Priority'] = '1'
            message['X-MSMail-Priority'] = 'High'
            message['Importance'] = 'High'
        elif priority == 'low':
            message['X-Priority'] = '5'
            message['X-MSMail-Priority'] = 'Low'
            message['Importance'] = 'Low'
        
        # Add body text
        message.attach(MIMEText(body, 'plain'))
        
        # Create SMTP session
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        
        # Send email
        server.send_message(message)
        server.quit()
        
        priority_str = f" (priority: {priority})" if priority else ""
        logger.info(f"Custom email sent successfully to {recipient_email}{priority_str}")
        return True
    except Exception as e:
        logger.error(f"Error sending custom email: {str(e)}")
        return False