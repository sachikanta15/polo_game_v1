# Generated by Django 4.2.6 on 2024-11-19 01:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('otp_app', '0006_alter_userprofile_select_site'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='select_site',
            field=models.URLField(blank=True, max_length=255, null=True),
        ),
    ]