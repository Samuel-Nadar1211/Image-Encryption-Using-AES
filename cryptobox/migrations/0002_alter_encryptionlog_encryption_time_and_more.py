# Generated by Django 5.1.2 on 2024-11-05 10:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cryptobox', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='encryptionlog',
            name='encryption_time',
            field=models.DurationField(),
        ),
        migrations.AlterField(
            model_name='encryptionlog',
            name='image_size',
            field=models.IntegerField(),
        ),
    ]