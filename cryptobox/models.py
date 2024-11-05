from django.db import models
from django.core.exceptions import ValidationError
from django.db.models import Q, CheckConstraint
from datetime import timedelta

# Create your models here.
class EncryptionLog(models.Model):
    ACTION_CHOICES = [('ENCRYPT', 'Encrypt'), ('DECRYPT', 'Decrypt')]
    STATUS_CHOICES = [('SUCCESS', 'Success'), ('FAILURE', 'Failure')]
    IMAGE_CHOICES = [('png', 'PNG'), ('jpg', 'JPG'), ('gif', 'GIF')]
    KEY_CHOICES = [(16, '16 Bytes'), (24, '24 Bytes'), (32, '32 Bytes')]  # Bytes

    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    image_size = models.IntegerField()
    key_size = models.IntegerField(choices=KEY_CHOICES)
    encryption_time = models.DurationField()
    source_image = models.CharField(max_length=10, choices=IMAGE_CHOICES)
    image_conversion_time = models.DurationField(blank=True, null=True, help_text="Time taken to convert image to PNG format (if applicable)")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} at {self.created_at} - {self.status}"
    
    def save(self, *args, **kwargs):
        if self.source_image == 'png':
            self.image_conversion_time = None
        super().save(*args, **kwargs)

    def clean(self):
        if self.image_size <= 0:
            raise ValidationError("Image size must be greater than 0.")

        if self.image_conversion_time is not None:
            if self.image_conversion_time <= timedelta(0):
                raise ValidationError("Image conversion time must be greater than 0")
            if self.image_conversion_time >= self.encryption_time:
                raise ValidationError("Image conversion time must be less than encryption time.")
        else:
            if self.encryption_time <= timedelta(0):
                raise ValidationError("Image encryption time must be greater than 0.")

        super().clean()

    class Meta:
        ordering = ['-created_at']
        constraints = [
            CheckConstraint(check=Q(image_size__gt=0), name="image_size_gt_0"),
            CheckConstraint(
                check=Q(image_conversion_time__lt=models.F('encryption_time')) & 
                      Q(image_conversion_time__gt=timedelta(0)),
                name="conversion_time_range"
            ),
        ]