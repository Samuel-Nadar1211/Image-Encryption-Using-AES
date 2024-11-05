from django.shortcuts import render
from django.http import HttpResponse, FileResponse
from django.conf import settings

from .aes import cipher, decipher
from PIL import Image
from datetime import timedelta
import time
from io import BytesIO
import os
import hashlib

from .models import EncryptionLog


# Create your views here.
def index(request):
    return render(request, 'index.html')

def encrypt(request):
    if request.method == 'POST':
        plain_image = request.FILES.get('plain_image')
        key_hex = request.POST.get('encrypt_key')
        key = [int(key_hex[i : i + 2], 16) for i in range(0, len(key_hex), 2)]

        start_time = time.time()
        image_conversion_time = None
        source_image_format = plain_image.content_type.split('/')[-1].lower()
        if source_image_format == 'jpeg':
            source_image_format = 'jpg'

        if plain_image.content_type != 'image/png':
            conversion_start_time = time.time()
            
            # Convert to PNG using PIL
            image = Image.open(plain_image)
            output = BytesIO()
            image.save(output, format='PNG')
            image_data = output.getvalue()

            image_conversion_time = timedelta(seconds=time.time() - conversion_start_time)
        else:
            image_data = plain_image.read()

        image_data = image_data + b'\x00' * ((16 - len(image_data) % 16) % 16)
        sha512_hash = hashlib.sha512(image_data).digest()       # Compute Hash Value
        
        encrypted_file_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_image.bin')
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(sha512_hash)

            for i in range(0, len(image_data), 16):
                block = image_data[i : i + 16]
                encrypted_block = cipher(block, key)
                ef.write(bytes(encrypted_block))

        encryption_duration = timedelta(seconds=time.time() - start_time)
        EncryptionLog.objects.create(
            action='ENCRYPT',
            status='SUCCESS',
            image_size=len(image_data),
            key_size=len(key),
            encryption_time=encryption_duration,
            source_image=source_image_format,
            image_conversion_time=image_conversion_time
        )

        response = FileResponse(open(encrypted_file_path, 'rb'), content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename="encrypted_file.bin"'
        # os.remove(encrypted_file_path)
        return response

    return render(request, 'index.html')

def decrypt(request):
    if request.method == 'POST':
        encrypted_file = request.FILES.get('encrypted_file')
        key_hex = request.POST.get('decrypt_key')
        key = [int(key_hex[i: i + 2], 16) for i in range(0, len(key_hex), 2)]

        start_time = time.time()

        # Save uploaded encrypted file temporarily
        encrypted_file_path = os.path.join(settings.MEDIA_ROOT, encrypted_file.name)
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_file.read())

        # Read the hash and encrypted data
        with open(encrypted_file_path, 'rb') as fin:
            sha512_hash = fin.read(64)  # SHA-512 hash is 64 bytes
            encrypted_data = fin.read()  # Remaining data

        decrypted_data = bytearray()
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i: i + 16]
            decrypted_block = decipher(block, key)
            decrypted_data.extend(decrypted_block)

        computed_hash = hashlib.sha512(decrypted_data).digest()
        encryption_duration = timedelta(seconds=time.time() - start_time)

        if computed_hash != sha512_hash:
            # Log failure if hash doesn't match
            EncryptionLog.objects.create(
                action='DECRYPT',
                status='FAILURE',
                image_size=len(decrypted_data),
                key_size=len(key),
                encryption_time=encryption_duration,
            )
            return render(request, 'error.html')

        # Save the decrypted image
        image_file_path = os.path.join(settings.MEDIA_ROOT, 'decrypted_image.png')
        with open(image_file_path, 'wb') as image_file:
            image_file.write(decrypted_data)

        # Log success
        EncryptionLog.objects.create(
            action='DECRYPT',
            status='SUCCESS',
            image_size=len(decrypted_data),
            key_size=len(key),
            encryption_time=encryption_duration,
        )

        with open(image_file_path, 'rb') as image_file:
            response = HttpResponse(image_file.read(), content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="decrypted_image.png"'

        return response

    return render(request, 'index.html')
