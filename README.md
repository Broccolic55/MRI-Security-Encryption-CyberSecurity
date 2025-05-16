# MRI-Security-Encryption-CyberSecurity
Securing MRI Images Using Steganography and Cryptography encryption

Abstract:
  With the evolution of medical imaging technology, protecting the privacy, integrity, and security of MRI images 
has become a significant problem. This work proposes a multi-layer security framework using steganography and 
triple layering cryptographical encryption (AES-256, ASCON, and ECC) for securing sensitive medical data. First, 
the system hides the MRI image into a cover image by using the Least Significant Bit (LSB) steganography. Next, 
three levels of encryption are applied to the stego picture. Users (doctors or patients) need to authenticate 
themselves using hospital provided credentials, followed by some verification process on the user side of the system 
to retrieve the image, after which, it restores the original MRI picture while maintaining its security using multi
layer decryptions. The system also provides a robust security approach in the healthcare data management that 
prevents the data from unauthorized access. 
Keywords: MRI Images, Steganography, Cryptographical Encryption, AES-128, ASCON, ECC, Stego Image. 

Modules:
• Image handler for admin & user  
• Auto cover image selector & Steganography  
• Triple layer of encryption  
• Authenticator and Decryption  
• Integrity checker & Alert system
