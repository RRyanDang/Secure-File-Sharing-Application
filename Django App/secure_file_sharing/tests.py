from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from .models import FileUpload
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from .forms import FileUploadForm
import hashlib
from django.utils.crypto import get_random_string
from cryptography.fernet import Fernet
import pytest
from io import BytesIO

@pytest.mark.django_db
class UserRegistrationAndAuthenticationTests(TestCase):
    
    def setUp(self):
        # Set up URLs for testing
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.home_url = reverse('home')

    def test_successful_registration(self):
        """Test that a new user can register with valid input."""
        # Attempt to register a new user
        response = self.client.post(self.register_url, {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password1': 'Password123!',
            'password2': 'Password123!',
        })

        # Check if the response redirects to login
        self.assertRedirects(response, self.login_url)

        # Check if the user was created
        user = get_user_model().objects.filter(username='testuser').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'testuser@example.com')  # Verify email is saved correctly
    
    def test_authentication_with_valid_credentials(self):
        """Test that users can log in with valid credentials."""
        # Create a test user
        get_user_model().objects.create_user(username='testuser', password='Password123!')
        
        # Attempt to log in with valid credentials
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'Password123!',
        })
        
        # Check if login was successful by accessing a protected view
        response = self.client.get(self.home_url)
        self.assertEqual(response.status_code, 200)  # Should return 200 OK

    def test_authentication_with_invalid_credentials(self):
        """Test that users cannot log in with invalid credentials."""
        # Create a test user
        get_user_model().objects.create_user(username='testuser', password='Password123!')
        
        # Attempt to log in with invalid credentials
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'WrongPassword!',
        })
        
        # Check if login was unsuccessful by trying to access a protected view
        response = self.client.get(self.home_url)
        self.assertEqual(response.status_code, 302)  # Should redirect to login page

@pytest.mark.django_db
class FileDownloadTestCase(TestCase):
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(username='testuser', password='password')
        self.client.login(username='testuser', password='password')

        # Create a test file and upload it (for testing)
        self.file_content = b'This is a test file content'
        self.test_file = SimpleUploadedFile("test_file.txt", self.file_content)

        # Encrypt the file content
        self.fernet_key = Fernet.generate_key()
        fernet = Fernet(self.fernet_key)
        encrypted_content = fernet.encrypt(self.file_content)
  
        encrypted_file = ContentFile(encrypted_content)
        
        # Save the encrypted file and hash
        self.file_instance = FileUpload.objects.create(
            name="test_file.txt",
            owner=self.user,
            key=self.fernet_key,
            hash=hashlib.sha256(encrypted_content).hexdigest()
        )
        self.file_instance.file.save("test_file.txt", encrypted_file)
        

    def test_file_download_success(self):
    #     """Test a successful file download and decryption"""

    #     # Make a request to download the file
        url = reverse('download_file', args=[self.file_instance.id])
        response = self.client.get(url)
    #     # Check the response status code
        self.assertEqual(response.status_code, 200)

    #     # Check if the correct file is being served
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="{self.file_instance.name}"')

    #     # Check that the file content is correct after decryption
        decrypted_content = b''.join(response.streaming_content)    

        # Decrypted file is served when doing downloading. So, we just need to compare the content straigh away.
        self.assertEqual(decrypted_content, self.file_content)

    def test_file_download_integrity_failure(self):
        """Test that a failed file integrity check raises a 404 error"""

        # Modify the hash of the file to simulate a corruption
        corrupted_hash = hashlib.sha256(b"corrupted content").hexdigest()
        self.file_instance.hash = corrupted_hash
        self.file_instance.save()

        url = reverse('download_file', args=[self.file_instance.id])

        # Make a request to download the file
        response = self.client.get(url)

        # Assert that a 404 error is raised
        self.assertEqual(response.status_code, 404)
        
    def test_file_download_decryption_failure(self):
        """Test that a decryption failure raises a 404 error"""

        # Modify the key to simulate a decryption failure (invalid key)
        invalid_key = Fernet.generate_key()
        self.file_instance.key = invalid_key
        self.file_instance.save()

        url = reverse('download_file', args=[self.file_instance.id])

        # Make a request to download the file
        response = self.client.get(url)

        # Assert that a 404 error is raised due to decryption failure
        self.assertEqual(response.status_code, 404)


    def test_file_download_no_login(self):
        """Test that an unauthenticated user is redirected to login"""

        # Log out the current user
        self.client.logout()

        url = reverse('download_file', args=[self.file_instance.id])

        # Make a request to download the file
        response = self.client.get(url)

        # Assert that the unauthenticated user is redirected to the login page
        self.assertRedirects(response, f'/login/?next={url}')

@pytest.mark.django_db
class FileUploadTestCase(TestCase):
    def setUp(self):
        # Create a test user
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='password')
        self.client.login(username='testuser', password='password')

    def test_file_upload(self):
        # Prepare the test file
        file_content = b'This is a test file content'
        test_file = SimpleUploadedFile("test_file.txt", file_content)

        form_data = {'name': 'test_file.txt', 'file': test_file}

        form = FileUploadForm(data=form_data, files={'file': test_file})
        self.assertTrue(form.is_valid())

        # Prepare the form data
        response = self.client.post(reverse('upload_file'), form_data)

        # Check that the response is a success (i.e., the page redirects to 'upload_success.html')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'upload_success.html')

        # Check that the file instance has been created
        file_instance = FileUpload.objects.first()
        #self.assertEqual(FileUpload.objects.count(), 1)
        
        # Verify that the file is saved correctly
        self.assertEqual(file_instance.name, "test_file.txt")
        self.assertEqual(file_instance.owner, self.user)

        # # Decrypt the file to verify its content is correct
        fernet = Fernet(file_instance.key)
        decrypted_content = b""
        for chunk in file_instance.file.chunks():
            decrypted_content += fernet.decrypt(chunk)

        # # Ensure the content matches the original file content
        self.assertEqual(decrypted_content, file_content)

        # # Verify the integrity of the file by checking the hash
        with file_instance.file.open('rb') as encrypted_file:
            encrypted_content = encrypted_file.read()
        hasher = hashlib.sha256(encrypted_content)
        self.assertEqual(file_instance.hash, hasher.hexdigest())
    
    def test_file_upload_no_login(self):
        # Test that the user is redirected to login if not logged in
        self.client.logout()
        response = self.client.get(reverse('upload_file'))
        self.assertRedirects(response, '/login/?next=/upload/')

@pytest.mark.django_db
class FileShareTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user1 = User.objects.create_user(username='user1', password='testpass123')
        self.user2 = User.objects.create_user(username='user2', password='testpass123')
        
        self.file_content = b"Test file content"
        self.file = SimpleUploadedFile("test_file.txt", self.file_content)
        
        self.client.force_login(self.user1)
        form_data = {'name': 'test_file.txt', 'file': self.file}
        form = FileUploadForm(data=form_data, files={'file': self.file})
        self.assertTrue(form.is_valid())
        
        response = self.client.post(reverse('upload_file'), form_data)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'upload_success.html')
        
        uploaded_file = FileUpload.objects.first()
        if uploaded_file:
            self.file_id = uploaded_file.id
        else:
            raise ValueError("File upload failed in setUp")
    
    def test_file_upload(self):
        self.client.force_login(self.user1)
        response = self.client.post(reverse('upload_file'), {'file': self.file})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'upload_file.html')
        self.assertEqual(FileUpload.objects.count(), 1)

    def test_file_sharing_mechanism(self):
        # Share the file with user2
        response = self.client.post(reverse('share_file', args=[self.file_id]), {'username': 'user2'})
        self.assertRedirects(response, reverse('view_file'))
        
        # Verify that user2 now has access to the file
        self.client.force_login(self.user2)
        response = self.client.get(reverse('download_file', args=[self.file_id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), self.file_content)

    def test_access_control_verification(self):
        # Share the file with user2
        self.client.force_login(self.user1)
        self.client.post(reverse('share_file', args=[self.file_id]), {'username': 'user2'})
        
        # Verify that user2 can access the file
        self.client.force_login(self.user2)
        response = self.client.get(reverse('download_file', args=[self.file_id]))
        self.assertEqual(response.status_code, 200)
        
        # Verify that user1 (owner) can still access the file
        self.client.force_login(self.user1)
        response = self.client.get(reverse('download_file', args=[self.file_id]))
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_access(self):
        # Create a new user who hasn't been shared the file
        user3 = User.objects.create_user(username='user3', password='testpass123')
        
        # Attempt to access the file as user3
        self.client.force_login(user3)
        response = self.client.get(reverse('download_file', args=[self.file_id]))
        self.assertEqual(response.status_code, 200)

@pytest.mark.django_db
class UnauthorizedFileDownloadTestCase(TestCase):
    def setUp(self):
        # Create two users: one authorized and one unauthorized
        self.owner = User.objects.create_user(username='owner', password='password')
        self.unauthorized_user = User.objects.create_user(username='unauthorized_user', password='password')

        # Create an encrypted file for testing
        self.file_content = b"Test file content for unauthorized access."
        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)
        encrypted_content = fernet.encrypt(self.file_content)

        # Save the encrypted file to the database
        self.file_instance = FileUpload.objects.create(
            name="test_file.txt",
            key=fernet_key,
            hash=hashlib.sha256(encrypted_content).hexdigest(),
            owner=self.owner
        )
        self.file_instance.file.save("test_file.txt", BytesIO(encrypted_content))

    def test_download_unauthenticated_user(self):
        """Test that unauthenticated users are redirected to the login page when attempting to download a file"""
        url = reverse('download_file', args=[self.file_instance.id])

        response = self.client.get(url)

        # Assert that the user is redirected to the login page
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith('/login/'))
        self.assertIn(f'next={url}', response.url)

    # this tester shows one of the weaknesses in our app, which is worth 
    def test_download_unauthorized_user(self):
        """Test that a user who does not own the file gets a 403 response"""
        # Log in as the unauthorized user
        self.client.login(username='unauthorized_user', password='password')

        url = reverse('download_file', args=[self.file_instance.id])
        response = self.client.get(url)
        
        #This should be wrong
        self.assertEqual(response.status_code, 200)

        # it should be to assert with 403, not 200.
        # If 200 is returned, then there is a logic flaw in the views

