# Import necessary modules
from django.shortcuts import render, get_object_or_404, redirect
from django.http import FileResponse
from django.core.files.base import ContentFile
from .forms import FileUploadForm, UserRegisterForm
from .models import FileUpload
from django.shortcuts import render
from django.http import Http404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import hashlib
from cryptography.fernet import Fernet
from .utils import generate_aes_key, encrypt_file_content, decrypt_file_content, generate_fernet_key
from io import BytesIO
from django.contrib.auth.models import User


# View for the home page
@login_required
def home(request):
    return render(request, 'main_ui.html')

# View to display all files
@login_required
def view_file(request):
    files = FileUpload.objects.all()
    return render(request, 'list_files2.html', {'files': files})

# View for file upload with AES encryption
@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']

            # Generate a unique AES key and encrypt the file
            fernet_key = Fernet.generate_key()
            fernet = Fernet(fernet_key)
            encrypted_content = b''
            for chunk in uploaded_file.chunks():
                encrypted_content += fernet.encrypt(chunk)

            # Save the encrypted file
            encrypted_file = ContentFile(encrypted_content, name=uploaded_file.name)

            # Create and save the FileUpload instance
            file_instance = FileUpload(
                name=uploaded_file.name,
                key=fernet_key,
                owner=request.user
            )
            file_instance.file.save(uploaded_file.name, encrypted_file)

            # Calculate and store the hash for integrity verification
            hasher = hashlib.sha256(encrypted_content)
            file_instance.hash = hasher.hexdigest()

            file_instance.save()
            return render(request, 'upload_success.html')
    else:
        form = FileUploadForm()
    return render(request, 'upload_file.html', {'form': form})

# View for file download with AES decryption
@login_required
def download_file(request, file_id):
    file_obj = get_object_or_404(FileUpload, id=file_id)

    # Read the encrypted file content
    with file_obj.file.open('rb') as encrypted_file:
        encrypted_content = encrypted_file.read()

    # Verify file integrity using hash
    hasher = hashlib.sha256(encrypted_content)
    calculated_hash = hasher.hexdigest()
    if calculated_hash != file_obj.hash:
        raise Http404("File integrity check failed. The file may be corrupted.")

    # Decrypt the file content
    try:
        fernet = Fernet(file_obj.key)
        decrypted_content = fernet.decrypt(encrypted_content)
    except Exception as e:
        raise Http404(f'File decryption failed: {e}')
    
    # Serve the decrypted file
    file_stream = BytesIO(decrypted_content)
    response = FileResponse(file_stream, as_attachment=True, filename=file_obj.name)
    return response

# View for user registration
def register(request):
    if request.method == "POST":
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get("username")
            messages.success(request, f'Your account has been created! You are now able to login.')
            return redirect("login")
    else:
        form = UserRegisterForm()
    return render(request, 'register.html', {"form": form})

# View for sharing a file with another user
@login_required
def share_file(request, file_id):
    original_file = get_object_or_404(FileUpload, id=file_id, owner=request.user)

    if request.method == 'POST':
        username = request.POST.get('username')
        user_to_share_with = get_object_or_404(User, username=username)

        # Create a new FileUpload instance for the shared file
        FileUpload.objects.create(
            owner=user_to_share_with,
            name=original_file.name,
            file=original_file.file,
            key=original_file.key,
            hash=original_file.hash
        )
        messages.success(request, f"File '{original_file.name}' successfully shared with {username}.")
        return redirect('view_file')

    return render(request, 'share_file.html', {'file': original_file})

# View for displaying and sharing user's files
@login_required
def my_files(request):
    owned_files = FileUpload.objects.filter(owner=request.user)

    if request.method == 'POST':
        file_id = request.POST.get('file_id')
        username = request.POST.get('username')
        
        try:
            file_to_share = get_object_or_404(FileUpload, id=file_id, owner=request.user)
            user_to_share_with = get_object_or_404(User, username=username)

            # Check if the user already owns the file
            if FileUpload.objects.filter(name=file_to_share.name, owner=user_to_share_with).exists():
                messages.error(request, f"User '{username}' already owns a file named '{file_to_share.name}'.")
            else:
                # Create a new FileUpload instance for the shared file
                FileUpload.objects.create(
                    owner=user_to_share_with,
                    name=file_to_share.name,
                    file=file_to_share.file,
                    key=file_to_share.key,
                    hash=file_to_share.hash
                )
                messages.success(request, f"File '{file_to_share.name}' successfully shared with {username}.")
        except User.DoesNotExist:
            messages.error(request, f"User '{username}' does not exist.")
        except Exception as e:
            messages.error(request, f"An error occurred while sharing the file: {str(e)}")

        return redirect('my_files')

    return render(request, 'share_files.html', {'owned_files': owned_files})

