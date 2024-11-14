from django.core.management.base import BaseCommand
from django.core.cache import cache
import redis
from django.conf import settings

class Command(BaseCommand):
    help = 'List all OTP data cached by test_cache command'

    def handle(self, *args, **kwargs):
        # Connect to Redis using redis-py to retrieve cached data
        redis_client = redis.StrictRedis.from_url(settings.CACHES['default']['LOCATION'])

        # Get all keys matching the OTP pattern
        keys = redis_client.keys('otp:*')

        if not keys:
            self.stdout.write(self.style.WARNING("No cached OTP data found."))
            return

        self.stdout.write(self.style.SUCCESS(f"Found {len(keys)} cached OTP entries:"))

        # Iterate through each key and retrieve the corresponding data
        for key in keys:
            # Get the cached data for each key
            cached_data = cache.get(key.decode('utf-8'))

            # Output the key and its corresponding cached data
            self.stdout.write(f"Key: {key.decode('utf-8')}")
            self.stdout.write("Cached Data:")
            for field, value in cached_data.items():
                self.stdout.write(f"  {field}: {value}")
            self.stdout.write("-" * 40)
