from django.db import models
import os
import base64
import hashlib
import logging as log
import pyotp
import threading
import time
from datetime import datetime, timedelta, timezone
from mongoengine import Document, StringField, DateTimeField
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Initialize logging
logger = log.getLogger(__name__)

class OTPManagement:
    def process_received_mobile_number(self, encrypted_mobile_number, document_id):
        try:
            # Create a document structure similar to the one expected from MongoDB
            document = {'mobile_number': encrypted_mobile_number, '_id': document_id}

            # Start the decryption and OTP generation process
            self.process_decryption_and_otp(document)
        except Exception as e:
            logger.error(f"Error processing the received mobile number: {str(e)}")
            raise

    def decrypt_mobile_number(self, document):
        try:
            # Log the start time before decryption
            start_time = time.time()
            
            kv_uri = os.getenv("AZURE_KEY_VAULT_URI")
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=kv_uri, credential=credential)

            key_name = f"encryption-key-{document['_id']}"
            encryption_key_secret = client.get_secret(key_name)
            encryption_key = bytes.fromhex(encryption_key_secret.value)

            encrypted_data = base64.b64decode(document['mobile_number'])
            iv = encrypted_data[:16]
            encrypted_mobile_number = encrypted_data[16:]

            cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_mobile_number = decryptor.update(encrypted_mobile_number) + decryptor.finalize()

            # Log the time taken for decryption
            decryption_time = time.time() - start_time
            logger.info(f"Time taken for decryption: {decryption_time:.6f} seconds")

            return decrypted_mobile_number.decode('utf-8')

        except Exception as e:
            logger.error(f"Failed to decrypt mobile number: {str(e)}")
            return None

    def generate_totp(self, mobile_number):
        # Use the mobile number as the base for the TOTP secret (or hash it for extra security)
        totp_secret = pyotp.random_base32()  # This secret should be securely stored and linked to the mobile number

        # Create a TOTP object with a 10-minute validity (600 seconds)
        t_otp = pyotp.TOTP(totp_secret, interval=600)

        # Generate the OTP
        totp = t_otp.now()

        # Here you would store the TOTP secret in your database associated with the mobile number

        return totp

    def process_decryption_and_otp(self, document):
        try:
            decrypted_mobile_number = self.decrypt_mobile_number(document)
            if decrypted_mobile_number:
                otp = self.generate_totp(decrypted_mobile_number)
                totp = pyotp.random_base32()

                logger.info(f'Generated OTP: {otp}')

                # Create a new entry with the new OTP and TOTP secret
                TPMDocument.create_entry(decrypted_mobile_number, otp, totp)
            else:
                logger.error("Failed to decrypt mobile number.")
        except Exception as e:
            logger.error(f"Error in decryption or OTP generation process: {str(e)}")

class TPMDocument(Document):
    _id = StringField(primary_key=True)
    mobile_number = StringField(required=True)
    mobile_number_hash = StringField(required=True)
    otp_hash = StringField(required=True)
    totp = StringField(required=True)
    service_prefix = StringField(required=True)
    created_at = DateTimeField(default=datetime.now(timezone.utc))
    expiry_at = DateTimeField()
    status = StringField(default="active")

    meta = {
        'db_alias': 'verification_db',
        'collection': 'otp_management_database',
        'time_series': {
            'timeField': 'create_at',
            'metaField': 'service_prefix'
        },
        'indexes': [
            {
                'fields': ['expiry_at'],
                'expireAfterSeconds': 600,
            },
            {
                'fields': ['mobile_number'],
            },
            {
                'fields': ['mobile_number_hash'],
            },
            {
                'fields': ['otp_hash'],
            },
            {
                'fields': ['totp'],
            },
            {
                'fields': ['status'],
            }
        ]
    }

    @classmethod
    def generate_custom_id(cls, mobile_number):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        hashed_number = hashlib.md5(mobile_number.encode()).hexdigest()[:10]
        random_suffix = ''.join(os.urandom(4).hex().upper() for _ in range(3))
        custom_id = f"TPM-{timestamp}-{hashed_number}-{random_suffix}"
        return custom_id

    @classmethod
    def encrypt_field(cls, field, encryption_key):
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_field = encryptor.update(field.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_field).decode('utf-8')

    @classmethod
    def store_encryption_key(cls, key_name, encryption_key, expiry_at=None):
        try:
            kv_uri = os.getenv("AZURE_KEY_VAULT_URI")
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=kv_uri, credential=credential)

            # Convert encryption_key to hex if it's in bytes
            if isinstance(encryption_key, bytes):
                encryption_key = encryption_key.hex()

            # Store with expiry for TPMDocument, without expiry for UserProfile
            if expiry_at:
                client.set_secret(key_name, encryption_key, expires_on=expiry_at)
            else:
                client.set_secret(key_name, encryption_key)
        except Exception as e:
            logger.error(f"Failed to store encryption key: {str(e)}")
            raise Exception(f"Failed to store encryption key: {str(e)}")

    @classmethod
    def hash_mobile_number(cls, mobile_number):
        """Creates a hash of the mobile number for lookup."""
        return hashlib.sha256(mobile_number.encode()).hexdigest()

    @classmethod
    def delete_existing_entry(cls, mobile_number):
        try:
            mobile_number_hash = cls.hash_mobile_number(mobile_number)
            existing_entry = cls.objects(mobile_number_hash=mobile_number_hash).first()

            if existing_entry:
                def async_delete():
                    try:
                        # Delete the associated encryption key from Azure Key Vault
                        kv_uri = os.getenv("AZURE_KEY_VAULT_URI")
                        credential = DefaultAzureCredential()
                        client = SecretClient(vault_url=kv_uri, credential=credential)

                        key_name = f"encryption-key-{existing_entry._id}"
                        client.begin_delete_secret(key_name)

                        # Delete the entry from MongoDB
                        existing_entry.delete()
                    except Exception as e:
                        logger.error(f"Failed to delete existing entry or encryption key: {str(e)}")
                        raise
                
                delete_thread = threading.Thread(target=async_delete)
                delete_thread.start()

        except Exception as e:
            logger.error(f"Error while checking for existing entry: {str(e)}")

    @classmethod
    def create_entry(cls, mobile_number, otp, totp):
        # Hash the mobile number and OTP
        mobile_number_hash = cls.hash_mobile_number(mobile_number)
        otp_hash = hashlib.sha256(otp.encode()).hexdigest()

        # Delete any existing entry for the same mobile number
        cls.delete_existing_entry(mobile_number)

        # Generate encryption key
        encryption_key = os.urandom(32)  # 256-bit key

        # Encrypt the fields
        encrypted_mobile_number = cls.encrypt_field(mobile_number, encryption_key)
        encrypted_totp = cls.encrypt_field(totp, encryption_key)

        # Create custom ID
        custom_id = cls.generate_custom_id(mobile_number)
        created_at = datetime.now(timezone.utc)
        expiry_at = created_at + timedelta(seconds=600)

        # Create the document
        entry = cls(
            _id=custom_id,
            mobile_number=encrypted_mobile_number,
            mobile_number_hash=mobile_number_hash,
            otp_hash=otp_hash,
            totp=encrypted_totp,
            service_prefix="TPM",
            created_at=created_at,
            expiry_at=expiry_at,
            status="active"
        )

        # Store the document and encryption key
        def store_data():
            try:
                key_name = f"encryption-key-{custom_id}"
                cls.store_encryption_key(key_name, encryption_key, expiry_at)
                entry.save()
            except Exception as e:
                logger.error(f"Failed to store data: {str(e)}")
                raise

        store_thread = threading.Thread(target=store_data)
        store_thread.start()

        return entry

class OTPVerification:
    @classmethod
    def verify_otp(cls, mobile_number_hash, otp_hash):
        try:
            # Query MongoDB to retrieve the document with the given mobile_number_hash
            document = TPMDocument.objects(mobile_number_hash=mobile_number_hash).first()

            if not document:
                logger.warning(f"Mobile number hash was not found in the database.")
                return "not_found"

            # Get the current time as a timezone-aware datetime in UTC
            current_time = datetime.now(timezone.utc)

            # Ensure document expiry_at is timezone-aware
            if document.expiry_at.tzinfo is None:
                document.expiry_at = document.expiry_at.replace(tzinfo=timezone.utc)

            # Check if the OTP has expired based on status or expiry time
            if document.status == "expired" or document.expiry_at < current_time:
                logger.warning(f"OTP for mobile number hash {mobile_number_hash} has expired or is already used.")
                return "expired"

            # Compare the OTP hash
            if document.otp_hash == otp_hash:
                # Mark OTP as expired after successful verification
                document.update(set__status="expired")
                document.reload()
                
                return "success"
            else:
                logger.warning(f"Verification failed.")
                return "invalid", None
        
        except Exception as e:
            logger.error(f"Error during OTP verification: {str(e)}")
            return "error", None


