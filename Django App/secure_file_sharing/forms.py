from django import forms  # Import Django forms module
from django.contrib.auth.models import User  # Import the User model for authentication
from django.contrib.auth.forms import UserCreationForm  # Import UserCreationForm for user registration
from .models import FileUpload  # Import the FileUpload model

# User registration form that extends the built-in UserCreationForm
class UserRegisterForm(UserCreationForm):
    email = forms.EmailField()  # Add an email field to the registration form

    class Meta:
        model = User  # Specify the model to use for this form
        fields = ['username', 'email', 'password1', 'password2']  # Fields to include in the form

# Form for uploading files, based on the FileUpload model
class FileUploadForm(forms.ModelForm):
    class Meta:
        model = FileUpload  # Specify the model to use for this form
        fields = ['name', 'file']  # Fields to include in the form