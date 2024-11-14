from django.core.management.base import BaseCommand
from django.core.cache import cache
import hashlib
import logging as log

logger = log.getLogger(__name__)

class OTPVerification:
    def verify_otp(self, mobile_number_hash, otp_hash):
        try:
            # Retrieve the cached data
            cache_key = f"otp:{mobile_number_hash}"
            cached_data = cache.get(cache_key)

            if cached_data:
                # Compare the OTP hash and mobile number hash
                if cached_data['otp_hash'] == otp_hash and cached_data['mobile_number_hash'] == mobile_number_hash:
                    logger.info("OTP verification successful.")
                    return True
                else:
                    logger.warning("OTP verification failed: OTP or mobile number does not match.")
                    return False
            else:
                logger.warning("OTP verification failed: No cached data found.")
                return False

        except Exception as e:
            logger.error(f"Error during OTP verification: {str(e)}")
            return False


class Command(BaseCommand):
    help = 'Simulate caching and verification of mobile number and OTP'

    def handle(self, *args, **kwargs):
        # Request the user to enter the mobile number and OTP
        mobile_number = input("Enter the mobile number (format: +91XXXXXXXXXX): ").strip()
        otp = input("Enter the 6-digit OTP: ").strip()

        # Validate mobile number and OTP
        if not mobile_number.startswith("+91") or not mobile_number[3:].isdigit() or len(mobile_number[3:]) != 10:
            self.stdout.write(self.style.ERROR("Invalid mobile number format. Please use +91XXXXXXXXXX format."))
            return

        if not otp.isdigit() or len(otp) != 6:
            self.stdout.write(self.style.ERROR("Invalid OTP. Please enter a 6-digit numeric OTP."))
            return

        # Hash the mobile number and OTP
        mobile_number_hash = hashlib.sha256(mobile_number.encode()).hexdigest()
        otp_hash = hashlib.sha256(otp.encode()).hexdigest()

        # Cache both hashed mobile number and OTP as a dictionary with a TTL of 10 minutes
        cache_key = f"otp:{mobile_number_hash}"
        cache_value = {
            "mobile_number_hash": mobile_number_hash,
            "otp_hash": otp_hash
        }
        cache.set(cache_key, cache_value, timeout=600)  # 600 seconds = 10 minutes

        logger.info(f"Storing in cache with key: {cache_key}")

        # Retrieve and display the cached data to verify it
        cached_data = cache.get(cache_key)

        if cached_data:
            self.stdout.write(self.style.SUCCESS(f"Successfully cached and retrieved data: {cached_data}"))
        else:
            self.stdout.write(self.style.ERROR("Failed to cache or retrieve the data."))
            return

        # Now, simulate the verification process
'''        verification_service = OTPVerification()
        verification_result = verification_service.verify_otp(mobile_number_hash, otp_hash)

        if verification_result:
            self.stdout.write(self.style.SUCCESS("OTP verification successful."))
        else:
            self.stdout.write(self.style.ERROR("OTP verification failed."))'''
