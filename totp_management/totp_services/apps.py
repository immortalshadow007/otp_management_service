from django.apps import AppConfig
import logging as log

logger = log.getLogger(__name__)

class TotpServicesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'totp_services'

    # Any startup task for the totp_services app can be included here
    def ready(self):
        logger.info('totp_services app is ready')
