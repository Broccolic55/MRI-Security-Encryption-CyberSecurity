import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from functools import lru_cache


class ECCCipher:
    def __init__(self, private_key=None):
        if private_key is None:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            self.private_key = serialization.load_pem_private_key(
                private_key, password=None
            )
        self.public_key = self.private_key.public_key()
        # Cache the public key PEM to avoid regenerating it
        self._public_key_pem_cache = None
        self._private_key_pem_cache = None

    def get_private_key_pem(self):
        if not self._private_key_pem_cache:
            self._private_key_pem_cache = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        return self._private_key_pem_cache

    def get_public_key_pem(self):
        if not self._public_key_pem_cache:
            self._public_key_pem_cache = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        return self._public_key_pem_cache

    # Cache public key loading to improve repeated operations
    @staticmethod
    @lru_cache(maxsize=32)
    def _load_public_key(key_data):
        return serialization.load_der_public_key(base64.b64decode(key_data))

    def encrypt(self, plaintext, recipient_public_key=None):
        # Fast path for bytes
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')

        # Determine which public key to use
        if recipient_public_key is None:
            public_key = self.public_key
        else:
            # Use cached key loading
            public_key = self._load_public_key(recipient_public_key)

        # Generate ephemeral key more efficiently
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

        # Derive key with a simplified info parameter
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'BrainSecureX-ECC'  # Shorter info parameter
        ).derive(shared_secret)

        # Generate IV and pad data in one step
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Create and use cipher in one step
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Get ephemeral public key more efficiently
        ephemeral_public_key_bytes = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Encode values once
        eph_key_b64 = base64.b64encode(ephemeral_public_key_bytes).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        return {
            'ephemeral_public_key': eph_key_b64,
            'iv': iv_b64,
            'ciphertext': ciphertext_b64
        }

    def decrypt(self, encrypted_data):
        # Load ephemeral public key using cached method
        ephemeral_public_key = self._load_public_key(encrypted_data['ephemeral_public_key'])

        # Perform key exchange and derivation in one logical block
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'BrainSecureX-ECC'  # Match the shorter info parameter
        ).derive(shared_secret)

        # Decode base64 values once
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])

        # Create and use cipher in one block
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad data efficiently
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()

    def sign(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message, signature, public_key=None):
        if isinstance(message, str):
            message = message.encode('utf-8')
        signature_bytes = base64.b64decode(signature)
        public_key = public_key or self.public_key
        try:
            public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def encrypt_key(self, key_data, recipient_public_key=None):
        """
        Encrypt key data using ECC
        
        Args:
            key_data (str): Key data to encrypt (usually combined keys)
            recipient_public_key (str, optional): Recipient's public key
            
        Returns:
            str: Encrypted key data in serialized form
        """
        # Encrypt the key data using the encrypt method
        encrypted = self.encrypt(key_data, recipient_public_key)
        
        # Serialize to JSON string for storage
        return json.dumps(encrypted)
    
    def decrypt_key(self, encrypted_key_data):
        """
        Decrypt key data encrypted with encrypt_key
        
        Args:
            encrypted_key_data (str): Encrypted key data in serialized form
            
        Returns:
            bytes: Decrypted key data
        """
        # Parse the JSON string
        encrypted = json.loads(encrypted_key_data)
        
        # Decrypt using the decrypt method
        return self.decrypt(encrypted)

if __name__ == "__main__":
    ecc = ECCCipher()
    public_key = base64.b64encode(ecc.get_public_key_pem()).decode('utf-8')
    print(f"Public Key: {public_key}")

    message = "Secret BrainSecureX message."
    encrypted = ecc.encrypt(message)
    print(f"Encrypted: {json.dumps(encrypted, indent=2)}")

    decrypted = ecc.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode('utf-8')}")

    signature = ecc.sign(message)
    print(f"Signature: {signature}")

    is_valid = ecc.verify_signature(message, signature)
    print(f"Signature Valid: {is_valid}")
