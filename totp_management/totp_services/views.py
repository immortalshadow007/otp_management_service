from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import OTPManagement, OTPVerification
from .serializers import EncryptedMobileNumberSerializer, OTPVerificationSerializer
import logging
import os

logger = logging.getLogger(__name__)

class OTPProcessView(APIView):
    """
    View to process the encrypted mobile number and generate OTP.
    """

    def post(self, request, *args, **kwargs):
        try:
            serializer = EncryptedMobileNumberSerializer(data=request.data)

            if not serializer.is_valid():
                logger.error("Encrypted mobile number is missing in the request")
                return Response({'error': 'Encrypted mobile number is required.'}, status=status.HTTP_400_BAD_REQUEST)

            # Extract validated data from the serializer
            document_id = serializer.validated_data['document_id']
            encrypted_mobile_number = serializer.validated_data['encrypted_mobile_number']

            # Initialize the OTPManagement class and process the encrypted mobile number
            otp_manager = OTPManagement()
            otp_manager.process_received_mobile_number(encrypted_mobile_number, document_id)
            
            return Response({'message': 'OTP generation process initiated successfully.'}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Failed to process the encrypted mobile number: {str(e)}")
            return Response({'error': 'An error occurred while processing the request.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class OTPVerificationView(APIView):
    """
    View to handle the OTP verification process.
    """

    def post(self, request, *args, **kwargs):

        # Extract the API key from the headers
        received_api_key = request.headers.get('V-API-KEY')
        expected_primary_api_key = os.getenv('PRIMARY_API_KEY_VERIFICATION')
        expected_secondary_api_key = os.getenv('SECONDARY_API_KEY_VERIFICATION')

        # Compare the received API key with the expected keys
        if received_api_key not in [expected_primary_api_key, expected_secondary_api_key]:
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

        # Proceed with OTP verification
        serializer = OTPVerificationSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        mobile_number_hash = serializer.validated_data['mobile_number_hash']
        otp_hash = serializer.validated_data['otp_hash']

        try:
            # Call the OTP verification method
            verification_result= OTPVerification.verify_otp(mobile_number_hash, otp_hash)

            if verification_result == "success":
                return Response({"status": "success", "message": "OTP verification successful."}, status=status.HTTP_200_OK)

            elif verification_result == "expired":
                return Response({"status": "fail", "message": "OTP has expired."}, status=status.HTTP_403_FORBIDDEN)

            elif verification_result == "invalid":
                return Response({"status": "fail", "message": "Incorrect OTP."}, status=status.HTTP_403_FORBIDDEN)

            elif verification_result == "not_found":
                return Response({"status": "fail", "message": "Mobile number not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.error(f"Error during OTP verification: {str(e)}")
            return Response({"status": "error", "message": "An error occurred during verification."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)