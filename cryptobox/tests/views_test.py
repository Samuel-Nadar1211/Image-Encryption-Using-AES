from django.test import TestCase
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
from cryptobox.models import EncryptionLog
from datetime import timedelta
import os

class EncryptionViewsTest(TestCase):
    
    def setUp(self):
        # Setup any test data or files
        self.valid_key = 'f7ad31a82e5b0c3f848d466754d2d16984e946115b83b2921c7a29484aecd66a'
        self.invalid_key = 'e7ad31a82e5b0c3f848d466754d2d16984e946115b83b2921c7a29484aecd66a'

        # Create a simple image file in memory for testing
        image_path = os.path.join(settings.MEDIA_ROOT, 'lock.png')
        with open(image_path, 'rb') as image_file:
            self.image_content = SimpleUploadedFile(
                'lock.png',
                image_file.read(),
                content_type='image/png'
            )
        
        invalid_file_path = os.path.join(settings.MEDIA_ROOT, 'invalid_file.bin')
        with open(invalid_file_path, 'rb') as invalid_file:
            self.invalid_file = SimpleUploadedFile(
                'invalid_file.bin',
                invalid_file.read(),
                content_type='application/octet-stream'  # or another non-image type
            )


    def test_encrypt_view_valid_request(self):
        """Test encrypt view with a valid image and key."""
        response = self.client.post(reverse('cryptobox:encrypt'), {
            'plain_image': self.image_content,
            'encrypt_key': self.valid_key
        })

        # Check that a file is returned and status code is correct
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="encrypted_file.bin"')

        # Check if the EncryptionLog entry was created
        self.assertEqual(EncryptionLog.objects.count(), 1)
        log_entry = EncryptionLog.objects.first()
        self.assertEqual(log_entry.action, 'ENCRYPT')
        self.assertEqual(log_entry.status, 'SUCCESS')


    def test_decrypt_view_valid_request(self):
        """Test decrypt view with a valid encrypted file and key."""
        # First, encrypt the file to have a valid encrypted file to test decrypting
        response = self.client.post(reverse('cryptobox:encrypt'), {
            'plain_image': self.image_content,
            'encrypt_key': self.valid_key
        })
        encrypted_file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_image.bin')

        # Ensure the encrypted file exists
        self.assertTrue(os.path.exists(encrypted_file_path))

        # Read the encrypted file for the decrypt request
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_content = SimpleUploadedFile(
                'encrypted_file.bin', encrypted_file.read(), content_type='application/octet-stream'
            )

            # Now test decryption
            response = self.client.post(reverse('cryptobox:decrypt'), {
                'encrypted_file': encrypted_content,
                'decrypt_key': self.valid_key
            })

            # Check that a file is returned and status code is correct
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response['Content-Type'], 'image/png')
            self.assertEqual(response['Content-Disposition'], 'attachment; filename="decrypted_image.png"')

            # Check if the EncryptionLog entry was created for the decrypt action
            self.assertEqual(EncryptionLog.objects.filter(action='DECRYPT').count(), 1)
            log_entry = EncryptionLog.objects.get(action='DECRYPT')
            self.assertEqual(log_entry.status, 'SUCCESS')
    
    
    def test_decrypt_view_invalid_file(self):
        """Test decrypt view with an invalid encrypted file."""

        # Now test decryption
        response = self.client.post(reverse('cryptobox:decrypt'), {
            'encrypted_file': self.invalid_file,
            'decrypt_key': self.valid_key
        })

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'error.html')
        
        # Verify that the EncryptionLog entry for failure is created
        self.assertEqual(EncryptionLog.objects.filter(status='FAILURE', action='DECRYPT').count(), 1)


    def test_decrypt_view_invalid_key(self):
        """Test decrypt view with an invalid encrypted key."""

        # First, encrypt the file to have a valid encrypted file to test decrypting
        response = self.client.post(reverse('cryptobox:encrypt'), {
            'plain_image': self.image_content,
            'encrypt_key': self.valid_key
        })
        encrypted_file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_image.bin')

        # Ensure the encrypted file exists
        self.assertTrue(os.path.exists(encrypted_file_path))

        # Read the encrypted file for the decrypt request
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_content = SimpleUploadedFile(
                'encrypted_file.bin', encrypted_file.read(), content_type='application/octet-stream'
            )

            # Now test decryption
            response = self.client.post(reverse('cryptobox:decrypt'), {
                'encrypted_file': encrypted_content,
                'decrypt_key': self.invalid_key
            })

            # Check that a file is returned and status code is correct
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, 'error.html')
            
            # Verify that the EncryptionLog entry for failure is created
            self.assertEqual(EncryptionLog.objects.filter(status='FAILURE', action='DECRYPT').count(), 1)