# myapp/validators.py
#Conditions and restrictions to be followed when handling any files
from django.core.exceptions import ValidationError

def validate_file_size(file):
    max_size_mb = 5  # Maximum file size in MB
    if file.size > max_size_mb * 1024 * 1024:
        raise ValidationError(f"File size cannot exceed {max_size_mb} MB.")
    
