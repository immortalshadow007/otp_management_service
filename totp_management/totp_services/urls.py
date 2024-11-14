from django.urls import path
from .views import OTPProcessView, OTPVerificationView

urlpatterns = [
    # Route for processing the encrypted mobile number and generating OTP
    path('process_otp/', OTPProcessView.as_view(), name='process_otp'),
    # Route for verifying OTP
    path('verify_otp/', OTPVerificationView.as_view(), name='verify_otp'),
]