from django.core.management.utils import get_random_secret_key
import random, string

# Path to your settings.py file
key_path = '/svol/license/KEY'

characters = string.digits + string.ascii_uppercase

# Generate a new secret key
# secret_key = get_random_secret_key()
key = ''.join(random.choice(characters) for _ in range(16))

# Write the new settings back to the file
with open(key_path, 'w') as file:
    file.write(key)

print("INFO: Product Key generated successfully!")