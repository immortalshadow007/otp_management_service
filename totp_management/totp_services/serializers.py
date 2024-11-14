from rest_framework import serializers

class EncryptedMobileNumberSerializer(serializers.Serializer):
    document_id = serializers.CharField(required=True)
    encrypted_mobile_number = serializers.CharField(required=True)

    def validate_encrypted_mobile_number(self, value):
        if not isinstance(value, str) or len(value) < 16:
            raise serializers.ValidationError("Invalid encrypted mobile number.")
        return value

class OTPVerificationSerializer(serializers.Serializer):
    mobile_number_hash = serializers.CharField(required=True)
    otp_hash = serializers.CharField(required=True)

    def validate_mobile_number_hash(self, value):
        if not isinstance(value, str) or len(value) != 64:  # Assuming SHA-256 hash
            raise serializers.ValidationError("Invalid mobile number hash.")
        return value

    def validate_otp_hash(self, value):
        if not isinstance(value, str) or len(value) != 64:  # Assuming SHA-256 hash
            raise serializers.ValidationError("Invalid OTP hash.")
        return value