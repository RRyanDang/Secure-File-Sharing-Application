from django.db import models
from django.contrib.auth.models import User
from .validators import validate_file_size

class FileUpload(models.Model):
    # ForeignKey to link each file to a user
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='file_uploads')
    
    # Name of the uploaded file
    name = models.CharField(max_length=255)
    
    # The actual file field with size validation
    file = models.FileField(upload_to='uploads/', validators=[validate_file_size])
    
    # Binary field to store encryption key
    key = models.BinaryField()
    
    # Store file hash for integrity checks
    hash = models.CharField(max_length=64, editable=False)
    
    # Automatically set to the date and time of upload
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # String representation of the model
        return f"{self.name} (uploaded by {self.owner.username})"