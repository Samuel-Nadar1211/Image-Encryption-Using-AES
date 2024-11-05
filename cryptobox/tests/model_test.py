from django.test import TestCase
from cryptobox.models import EncryptionLog
from django.core.exceptions import ValidationError
from datetime import timedelta

class EncryptionLogModelTest(TestCase):

    @classmethod
    def setUpTestData(self):
        self.encryption_log = EncryptionLog.objects.create(
            action="ENCRYPT",
            status="SUCCESS",
            image_size=1024,
            key_size=16,
            encryption_time=timedelta(seconds=2),
            source_image="jpg",
            image_conversion_time=timedelta(milliseconds=500),
        )


    def test_encryption_log_creation(self):
        self.assertEqual(EncryptionLog.objects.count(), 1)


    def test_action_choices(self):
        # Test valid choice
        self.encryption_log.action = "DECRYPT"
        self.encryption_log.full_clean()  # Validate before saving
        self.encryption_log.save()
        self.assertEqual(self.encryption_log.action, "DECRYPT")

        # Test invalid choice
        with self.assertRaises(ValidationError):
            self.encryption_log.action = "INVALID"
            self.encryption_log.full_clean()


    def test_status_choices(self):
        # Test valid choice
        self.encryption_log.status = "FAILURE"
        self.encryption_log.full_clean()
        self.encryption_log.save()
        self.assertEqual(self.encryption_log.status, "FAILURE")

        # Test invalid choice
        with self.assertRaises(ValidationError):
            self.encryption_log.status = "INVALID"
            self.encryption_log.full_clean()


    def test_source_image_choices(self):
        # Test valid choice
        self.encryption_log.source_image = "gif"
        self.encryption_log.full_clean()
        self.encryption_log.save()
        self.assertEqual(self.encryption_log.source_image, "gif")

        # Test invalid choice
        with self.assertRaises(ValidationError):
            self.encryption_log.source_image = "bmp"
            self.encryption_log.full_clean()


    def test_key_choices(self):
        # Test valid choice
        self.encryption_log.key_size = 32
        self.encryption_log.full_clean()
        self.encryption_log.save()
        self.assertEqual(self.encryption_log.key_size, 32)

        # Test invalid choice
        with self.assertRaises(ValidationError):
            self.encryption_log.key_size = 64
            self.encryption_log.full_clean()


    def test_image_conversion_time_nullable(self):
        """Test that image_conversion_time can be null"""
        self.encryption_log.image_conversion_time = None
        self.encryption_log.full_clean()
        self.encryption_log.save()
        self.assertIsNone(self.encryption_log.image_conversion_time)


    def test_string_representation(self):
        """Test the __str__ method of the EncryptionLog model"""
        self.assertEqual(
            str(self.encryption_log),
            f"{self.encryption_log.action} at {self.encryption_log.created_at} - {self.encryption_log.status}"
        )


    def test_ordering(self):
        """Test that EncryptionLog instances are ordered by '-created_at'"""
        log1 = EncryptionLog.objects.create(
            action="ENCRYPT",
            status="SUCCESS",
            image_size=2048,
            key_size=16,
            encryption_time=timedelta(seconds=3),
            source_image="jpg",
            image_conversion_time=timedelta(milliseconds=400),
        )
        # Fetch logs and verify ordering
        logs = EncryptionLog.objects.all()
        self.assertEqual(logs[0], log1)
        self.assertEqual(logs[1], self.encryption_log)


    def test_image_conversion_time_null_for_png(self):
        """Test that image_conversion_time is None when source_image is 'png'"""
        log = EncryptionLog(
            action='ENCRYPT',
            status='SUCCESS',
            image_size=1024,
            key_size=16,
            encryption_time=timedelta(seconds=2),
            source_image='png',
            image_conversion_time=timedelta(seconds=1)  # Should be reset to None
        )
        log.full_clean()  # Run validations
        log.save()
        self.assertIsNone(log.image_conversion_time, "image_conversion_time should be None for PNG images")


    def test_image_conversion_time_set_for_non_png(self):
        """Test that image_conversion_time can be set for non-PNG images"""
        log = EncryptionLog(
            action='ENCRYPT',
            status='SUCCESS',
            image_size=2048,
            key_size=16,
            encryption_time=timedelta(seconds=3),
            source_image='jpg',
            image_conversion_time=timedelta(seconds=1)
        )
        log.full_clean()
        log.save()
        self.assertIsNotNone(log.image_conversion_time, "image_conversion_time should not be None for non-PNG images")
        self.assertEqual(log.image_conversion_time, timedelta(seconds=1), "image_conversion_time should match the assigned value for non-PNG images")


    def test_image_size_greater_than_zero(self):
        """Test that image_size must be greater than 0"""
        log = EncryptionLog(
            action='ENCRYPT',
            status='SUCCESS',
            image_size=0,  # Invalid size
            key_size=16,
            encryption_time=timedelta(seconds=2),
            source_image='jpg',
            image_conversion_time=timedelta(seconds=1)
        )
        with self.assertRaises(ValidationError):
            log.full_clean()


    def test_image_conversion_time_greater_than_zero(self):
        """Test that image_conversion_time must be greater than 0 if set"""
        log = EncryptionLog(
            action='ENCRYPT',
            status='SUCCESS',
            image_size=1024,
            key_size=16,
            encryption_time=timedelta(seconds=2),
            source_image='jpg',
            image_conversion_time=timedelta(seconds=0)  # Invalid conversion time
        )
        with self.assertRaises(ValidationError):
            log.full_clean()  # This should raise a validation error


    def test_image_conversion_time_less_than_encryption_time(self):
        """Test that image_conversion_time must be less than encryption_time if set"""
        log = EncryptionLog(
            action='ENCRYPT',
            status='SUCCESS',
            image_size=1024,
            key_size=16,
            encryption_time=timedelta(seconds=2),
            source_image='jpg',
            image_conversion_time=timedelta(seconds=3)  # Invalid if greater than encryption time
        )
        with self.assertRaises(ValidationError):
            log.full_clean()  # This should raise a validation error


    def test_image_conversion_time_valid(self):
        """Test that invalid encryption_time raise a validation error if image_conversion_time is not set"""
        log = EncryptionLog(
            action='ENCRYPT',
            status='SUCCESS',
            image_size=1024,
            key_size=16,
            encryption_time=timedelta(seconds=0),  # Invalid encryption time
            source_image='png'
        )
        with self.assertRaises(ValidationError):
            log.full_clean()  # This should raise a validation error