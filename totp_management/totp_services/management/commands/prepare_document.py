from django.core.management.base import BaseCommand
from otp_services.models import OTPManagement
import logging

# Initialize logging
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Test the complete flow of models.py, including OTPManagement and TPMDocument processes.'

    def handle(self, *args, **kwargs):
        try:
            # Initialize OTPManagement
            otp_manager = OTPManagement()

            # Start monitoring the signup_auth_database collection
            logger.info("Starting the complete test of models.py...")
            otp_manager.monitor_collection()  # This will start the monitoring process

            # Note: The command will run indefinitely due to the Change Stream monitoring
            # For testing purposes, you might want to manually insert a document into
            # signup_auth_database to trigger the process.

        except Exception as e:
            logger.error(f"Error during the models.py test: {str(e)}")
            self.stdout.write(self.style.ERROR(f"Error during the models.py test: {str(e)}"))
