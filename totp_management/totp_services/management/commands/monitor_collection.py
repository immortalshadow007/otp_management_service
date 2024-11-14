from django.core.management.base import BaseCommand
from otp_services.models import OTPManagement
import logging

# Initialize logging
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Monitors the signup_auth_database collection for new entries using Change Streams.'

    def handle(self, *args, **kwargs):
        try:
            otp_manager = OTPManagement()
            self.stdout.write(self.style.SUCCESS("Initializing OTP Management..."))
            otp_manager.monitor_collection()  # This will handle everything as per the models.py script
        except Exception as e:
            logger.error(f"Error during monitoring: {str(e)}")
            self.stdout.write(self.style.ERROR(f"Error during monitoring: {str(e)}"))
        else:
            self.stdout.write(self.style.SUCCESS("Started monitoring the signup_auth_database collection."))

