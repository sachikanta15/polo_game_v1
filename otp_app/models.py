from django.db import models
import random
from django.contrib.auth.models import User

class OTPModel(models.Model):
    phone_number = models.CharField(max_length=15, unique=True, null=True)
    otp = models.CharField(max_length=6, blank=True, null=True)

    def generate_otp(self):
        """Generates a 6-digit OTP."""
        self.otp = str(random.randint(100000, 999999))
        self.save()

class UserProfile(models.Model):
    username = models.CharField(max_length=150, unique=True)
    country_code = models.CharField(max_length=5)
    phone_number = models.CharField(max_length=15, unique=True)
    select_site = models.CharField(max_length=255, blank=True, null=True)  # URLField for valid link format
