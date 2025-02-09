# from rest_framework import status
# from rest_framework.response import Response
# from rest_framework.decorators import api_view
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.core.exceptions import ValidationError
# from django.conf import settings
# import base64
# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# import os
# import re
# from django.core.validators import validate_email
# import requests

# #Generate Secret Key
# def generate_secret_key():
#     from django.core.management.utils import get_random_secret_key
#     with open('secret_key.txt', 'w') as f:
#         f.write(get_random_secret_key())

# # class PasswordValidator:
# #     @staticmethod
# #     def validate_password(password):
        
# #         if len(password) < 8:
# #             return False, "Password must be at least 8 characters long"
        
# #         if not re.search(r"[A-Z]", password):
# #             return False, "Password must contain at least one uppercase letter"
            
# #         if not re.search(r"[a-z]", password):
# #             return False, "Password must contain at least one lowercase letter"
            
# #         if not re.search(r"\d", password):
# #             return False, "Password must contain at least one number"
            
# #         if not re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password):
# #             return False, "Password must contain at least one special character"
        
# #         return True, "Password is strong"

# # class EmailValidator:
# #     @staticmethod
# #     def validate_email(email):
        
# #         try:
# #             # Use Django's built-in email validator
# #             validate_email(email)
            
# #             # Additional custom checks
# #             if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
# #                 return False, "Invalid email format"
                
# #             # Optional: Add disposable email domain check
# #             disposable_domains = ['tempmail.com', 'throwaway.com']  # Add more as needed
# #             domain = email.split('@')[1]
# #             if domain in disposable_domains:
# #                 return False, "Disposable email addresses are not allowed"
                
# #             return True, "Email is valid"
# #         except ValidationError:
# #             return False, "Invalid email format"

# class EncryptionHandler:
#     @staticmethod
#     def generate_key():
#         """Generate a Fernet key using the application's secret key"""
#         kdf = PBKDF2HMAC(
#             algorithm=hashes.SHA256(),
#             length=32,
#             salt=settings.SECRET_KEY.encode()[:16],
#             iterations=100000,
#         )
#         key = base64.urlsafe_b64encode(kdf.derive(settings.SECRET_KEY.encode()))
#         return key

#     @staticmethod
#     def decrypt_data(encrypted_data):
#         """Decrypt data using Fernet"""
#         if not encrypted_data:
#             return None
        
#         try:
#             f = Fernet(EncryptionHandler.generate_key())
#             decrypted_data = f.decrypt(encrypted_data.encode())
#             return decrypted_data.decode()
#         except Exception as e:
#             print(f"Decryption error: {str(e)}")
#             return None

#     @staticmethod
#     def encrypt_data(data):
#         """Encrypt data using Fernet"""
#         if not data:
#             return None
        
#         try:
#             f = Fernet(EncryptionHandler.generate_key())
#             encrypted_data = f.encrypt(data.encode())
#             return encrypted_data.decode()
#         except Exception as e:
#             print(f"Encryption error: {str(e)}")
#             return None

# @api_view(['POST'])
# def signup_view(request):
#     """Handle user signup with encrypted data"""
#     try:
#         # Decrypt incoming data
#         encrypted_name = request.data.get('name')
#         encrypted_email = request.data.get('email')
#         encrypted_password = request.data.get('password')
#         encrypted_confirm_password = request.data.get('confirm_password')

#         name = EncryptionHandler.decrypt_data(encrypted_name)
#         email = EncryptionHandler.decrypt_data(encrypted_email)
#         password = EncryptionHandler.decrypt_data(encrypted_password)
#         confirm_password = EncryptionHandler.decrypt_data(encrypted_confirm_password)

#         if not all([name, email, password, confirm_password]):
#             return Response({
#                 'error': EncryptionHandler.encrypt_data('Invalid or corrupted data')
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # is_valid_email, email_error = EmailValidator.validate_email(email)
#         # if not is_valid_email:
#         #     return Response({
#         #         'error': EncryptionHandler.encrypt_data(email_error)
#         #     }, status=status.HTTP_400_BAD_REQUEST)

#         # is_valid_password, password_error = PasswordValidator.validate_password(password)
#         # if not is_valid_password:
#         #     return Response({
#         #         'error': EncryptionHandler.encrypt_data(password_error)
#         #     }, status=status.HTTP_400_BAD_REQUEST)

#         if password != confirm_password:
#             return Response({
#                 'error': EncryptionHandler.encrypt_data('Passwords do not match')
#             }, status=status.HTTP_400_BAD_REQUEST)

#         if User.objects.filter(email=email).exists():
#             return Response({
#                 'error': EncryptionHandler.encrypt_data('Email already exists')
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # Create user
#         user = User.objects.create_user(
#             username=email,
#             email=email,
#             password=password,
#             first_name=name
#         )

#         return Response({
#             'message': EncryptionHandler.encrypt_data('User created successfully'),
#             'user_id': EncryptionHandler.encrypt_data(str(user.id))
#         }, status=status.HTTP_201_CREATED)

#     except Exception as e:
#         return Response({
#             'error': EncryptionHandler.encrypt_data(f'An error occurred: {str(e)}')
#         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# @api_view(['POST'])
# def login_view(request):
#     """Handle user login with encrypted data"""
#     try:
#         encrypted_email = request.data.get('email')
#         encrypted_password = request.data.get('password')

#         email = EncryptionHandler.decrypt_data(encrypted_email)
#         password = EncryptionHandler.decrypt_data(encrypted_password)

#         if not all([email, password]):
#             return Response({
#                 'error': EncryptionHandler.encrypt_data('Invalid or corrupted data')
#             }, status=status.HTTP_400_BAD_REQUEST)

#         # is_valid_email, email_error = EmailValidator.validate_email(email)
#         # if not is_valid_email:
#         #     return Response({
#         #         'error': EncryptionHandler.encrypt_data(email_error)
#         #     }, status=status.HTTP_400_BAD_REQUEST)

#         # Authenticate user
#         user = authenticate(username=email, password=password)

#         if user is not None:
#             refresh = RefreshToken.for_user(user)
            
#             response_data = {
#                 'message': EncryptionHandler.encrypt_data('Login successful'),
#                 'user_id': EncryptionHandler.encrypt_data(str(user.id)),
#                 'name': EncryptionHandler.encrypt_data(user.first_name),
#                 'email': EncryptionHandler.encrypt_data(user.email),
#                 'access_token': str(refresh.access_token),  # JWT tokens are already encrypted
#                 'refresh_token': str(refresh)
#             }
            
#             return Response(response_data, status=status.HTTP_200_OK)
#         else:
#             return Response({
#                 'error': EncryptionHandler.encrypt_data('Invalid email or password')
#             }, status=status.HTTP_401_UNAUTHORIZED)

#     except Exception as e:
#         return Response({
#             'error': EncryptionHandler.encrypt_data(f'An error occurred: {str(e)}')
#         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# ===============================================================================================



from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.models import User
from django.middleware.csrf import get_token
from django.contrib.auth import authenticate, login, logout
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .serializers import UserSerializer
import re
import requests


def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

@api_view(['POST'])
def signup_view(request):
    if request.method == 'POST':
        name = request.data.get('name', '').strip()
        email = request.data.get('email', '').strip()
        password = request.data.get('password', '')
        confirm_password = request.data.get('confirm_password', '')

        if not name:
            return Response({'error': 'Name is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

        password_valid, password_error = validate_password_strength(password)
        if not password_valid:
            return Response({'error': password_error}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.create_user(
                username=email, 
                password=password, 
                email=email,
                first_name=name
            )

            user.userprofile.save()
            
            return Response({
                'message': 'User created successfully', 
                'user_id': user.id
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                'error': 'An error occurred during user creation', 
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def login_view(request):
    if request.method == 'POST':
        email = request.data.get('email', '').strip()
        password = request.data.get('password', '')

        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=email, password=password)

        if user is not None:
            if not user.is_active:
                return Response({'error': 'User account is inactive'}, status=status.HTTP_403_FORBIDDEN)

            try:
                # login(request, user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    'message': 'Login successful',
                    'user_id': user.id,
                    'name': user.first_name,
                    'email': user.email,
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh)
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    'error': 'Token generation failed', 
                    'details': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)



# @api_view(['POST'])
# def login_view(request):
#     username = request.data.get('username')
#     password = request.data.get('password')
    
#     user = authenticate(username=username, password=password)
    
#     if user is not None:
#         login(request, user)
#         serializer = UserSerializer(user)
#         return Response({
#             'user': serializer.data,
#             'message': 'Login successful'
#         })
#     return Response({
#         'message': 'Invalid credentials'
#     }, status=400)

@api_view(['POST'])
def logout_view(request):
    logout(request)
    return Response({'message': 'Logged out successfully'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_detail(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['GET'])
def auth_status(request):
    if request.user.is_authenticated:
        serializer = UserSerializer(request.user)
        return Response({
            'is_authenticated': True,
            'user': serializer.data
        })
    return Response({
        'is_authenticated': False
    })
#=================================================================================================================



TRUECALLER_API_URL = "https://api4.truecaller.com/v1/identity" 
TRUECALLER_API_KEY = "aaliibvnbfdtv956atsvf_hdlzcxjb2v7numav46ljy"

@api_view(['POST'])
def lookup_phone_number(request):
    phone_number = request.data.get('phoneNumber')
    if not phone_number:
        return Response({"error": "Phone number is required"}, status=400)

    headers = {
        'Authorization': f'Bearer {TRUECALLER_API_KEY}'
    }
    params = {
        'phone': phone_number
    }

    response = requests.get(TRUECALLER_API_URL, headers=headers, params=params)

    if response.status_code == 200:
        return Response(response.json())
    else:
        return Response({"error": "Failed to fetch data", "details": response.text}, status=response.status_code)


