import os
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

class APIKeyMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Determine which endpoint is being accessed
        if request.path == '/api/totp/process_otp/':
            # Process OTP endpoint: requires M-API-KEY
            api_key = request.headers.get('M-API-KEY')
            valid_keys = [
                os.getenv('PRIMARY_API_KEY_TOTP_MANAGEMENT'),
                os.getenv('SECONDARY_API_KEY_TOTP_MANAGEMENT')
            ]
        elif request.path == '/api/totp/verify_otp/':
            # Verify OTP endpoint: requires V-API-KEY (from the frontend)
            api_key = request.headers.get('V-API-KEY')
            valid_keys = [
                os.getenv('PRIMARY_API_KEY_VERIFICATION'),
                os.getenv('SECONDARY_API_KEY_VERIFICATION')
            ]
        else:
            # If it's neither of the defined endpoints, don't validate API key
            return None

        # Check if the provided API key is valid
        if api_key not in valid_keys:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        # If the key is valid, allow the request to proceed
        return None
