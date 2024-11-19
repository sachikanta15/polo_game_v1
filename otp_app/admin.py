from django.contrib import admin
from .models import OTPModel, UserProfile


@admin.register(OTPModel)
class OTPModelAdmin(admin.ModelAdmin):
    """Admin configuration for OTPModel."""
    list_display = ('phone_number', 'otp')
    search_fields = ('phone_number',)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin configuration for UserProfile."""
    list_display = ('username', 'country_code', 'phone_number')
    search_fields = ('username', 'phone_number')
