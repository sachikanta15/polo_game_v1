from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.conf import settings
from twilio.rest import Client
from .models import OTPModel, UserProfile
import logging

# Configure logger
logger = logging.getLogger(__name__)

def send_otp(phone_number, otp):
    """Sends the OTP using Twilio."""
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=f"Your OTP is {otp}",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        logger.info(f"OTP sent to {phone_number}")
    except Exception as e:
        logger.error(f"Error sending OTP to {phone_number}: {e}")
        raise



def get_otp_view(request):
    """Handles OTP generation."""
    if request.method == 'POST':
        country_code = request.POST.get('country_code')
        phone_number = request.POST.get('phone_number')
        
        if not phone_number or not country_code:
            return JsonResponse({'status': 'error', 'message': 'Phone number and country code are required.'})

        full_phone_number = f"{country_code}{phone_number}"

        # Remove any existing OTPs for the phone number
        OTPModel.objects.filter(phone_number=full_phone_number).delete()

        try:
            # Generate and send OTP
            otp_entry = OTPModel.objects.create(phone_number=full_phone_number)
            otp_entry.generate_otp()
            send_otp(full_phone_number, otp_entry.otp)
            logger.info(f"OTP generated and sent for {full_phone_number}")
            return JsonResponse({'status': 'success', 'message': 'OTP sent successfully.'})
        except Exception as e:
            logger.error(f"Error generating or sending OTP for {full_phone_number}: {e}")
            return JsonResponse({'status': 'error', 'message': 'An error occurred while sending OTP.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def verify_otp_view(request):
    """Handles OTP verification."""
    if request.method == 'POST':
        country_code = request.POST.get('country_code')
        phone_number = request.POST.get('phone_number')
        otp = request.POST.get('otp')

        if not otp:
            return JsonResponse({'status': 'error', 'message': 'OTP is required.'})

        full_phone_number = f"{country_code}{phone_number}"

        try:
            otp_entry = OTPModel.objects.get(phone_number=full_phone_number, otp=otp)
            # Mark phone as verified in session
            request.session['verified_phone'] = full_phone_number
            logger.info(f"OTP verified successfully for {full_phone_number}")
            return JsonResponse({'status': 'success', 'message': 'OTP verified successfully.'})
        except OTPModel.DoesNotExist:
            logger.warning(f"Invalid OTP attempt for {full_phone_number}")
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})




def register_view(request):
    """Displays the registration form."""
    return render(request, 'send_otp.html')

from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import UserProfile
from django.urls import reverse
import logging

logger = logging.getLogger(__name__)

def create_user_view(request):
    """Handles user creation after OTP verification."""
    if request.method == 'POST':
        username = request.POST.get('username')
        country_code = request.POST.get('country_code')
        phone_number = request.POST.get('phone_number')
        select_site = request.POST.get('site')

        if not username or not phone_number or not country_code:
            return JsonResponse({'status': 'error', 'message': 'All fields are required.'})

        full_phone_number = f"{country_code}{phone_number}"

        # Ensure the phone number has been verified
        verified_phone = request.session.get('verified_phone')
        if verified_phone != full_phone_number:
            return JsonResponse({'status': 'error', 'message': 'Phone number not verified.'})

        # Create the user profile
        try:
            UserProfile.objects.create(
                username=username,
                country_code=country_code,
                phone_number=phone_number,
                select_site=select_site
            )
            # Clear the verified phone session after registration
            del request.session['verified_phone']

            # Redirect to the coffee page
            coffee_url = reverse('coffee')  # Get the URL for the 'coffee' page
            return JsonResponse({'status': 'success', 'redirect_url': coffee_url})

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': 'An error occurred while creating user profile.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})



def coffee(request):

    return render(request,'coffee.html')


from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as django_login
from django.contrib import messages

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_superuser:
                # Block superusers from logging in
                messages.error(request, "Invalid username or password.")
            else:
                # Log in regular users
                django_login(request, user)
                messages.success(request, "Logged in successfully!")
                return redirect("home")  # Redirect to the home page
        else:
            messages.error(request, "Invalid username or password.")
    
    return render(request, "login.html")


from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def home(request):
    return render(request, "home.html")




from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404

def admin_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None and user.is_superuser:  # Check if the user is an admin
            login(request, user)  # Use the login function from Django's auth
            return redirect('manage_users')  # Redirect to manage users page
        else:
            messages.error(request, 'Invalid username or password, or you do not have admin access.')
    
    return render(request, 'admin_login.html')

# Other views...

from django.contrib.auth import logout  # Import the logout function
from django.http import HttpResponseForbidden
from django.shortcuts import redirect

# Admin logout view
def admin_logout(request):
    if request.method == 'POST':
        logout(request)  # Logout the user
        return redirect('admin_login')  # Redirect to the admin login page
    else:
        return HttpResponseForbidden("Forbidden: Logout only allowed via POST request")

# Check if the user is an admin
def is_superuser(user):
    return user.is_superuser

# Admin manage users view
@login_required
@user_passes_test(is_superuser)
def manage_users(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
        else:
            User.objects.create_user(username=username, password=password)
            messages.success(request, f"User '{username}' has been created successfully.")

    users = User.objects.filter(is_superuser=False)  # List only non-superuser accounts
    return render(request, 'manage_users.html', {'users': users})

# Admin delete user view
@login_required
@user_passes_test(is_superuser)
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id, is_superuser=False)  # Prevent deletion of superusers
    user.delete()
    messages.success(request, f"User '{user.username}' has been deleted successfully.")
    return redirect('manage_users')
