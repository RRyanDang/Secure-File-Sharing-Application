# 🔐 SecureShare — Encrypted File Sharing with Django

Developed by: Ryan(myself) and Anthony.

A full-stack web application for securely uploading, storing, and sharing files with end-to-end encryption, integrity verification, and role-based access control.

---

## Features

- **AES/Fernet Encryption** — Every uploaded file is encrypted server-side before being written to disk. The encryption key is stored per-file in the database, never exposed to other users.
- **File Integrity Verification** — A SHA-256 hash of the encrypted file content is computed at upload time and verified on every download. Corrupted or tampered files are rejected.
- **User Authentication** — Full registration, login, and logout flows using Django's built-in auth system, with all sensitive views protected by `@login_required`.
- **Secure File Sharing** — File owners can share files with other registered users. A new `FileUpload` record (with the same key and hash) is created for the recipient, giving them isolated ownership without duplicating the ciphertext.
- **Access Control** — Downloads are gated by authentication. Only file owners or users the file has been explicitly shared with can access it.
- **Duplicate Prevention** — The sharing system checks for existing ownership before creating a new share record, preventing duplicate entries.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Django |
| Encryption | `cryptography` (Fernet / AES-128-CBC + HMAC) |
| Hashing | `hashlib` SHA-256 |
| Auth | Django `contrib.auth` |
| Testing | Django `TestCase`, `pytest-django` |
| Storage | Django `FileField` (local filesystem / configurable) |

---

## Project Structure

```
secure_file_sharing/
├── models.py        # FileUpload model with key, hash, and owner fields
├── views.py         # Upload, download, share, register, and home views
├── forms.py         # UserRegisterForm and FileUploadForm
├── urls.py          # URL routing
├── apps.py          # App configuration
└── tests.py         # Full test suite (auth, upload, download, sharing, access control)
```

---

## Getting Started

### Prerequisites

```bash
Python 3.10+
pip
```

### Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/secureshare.git
cd secureshare

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Apply migrations
python manage.py migrate

# Run the development server
python manage.py runserver
```

### Running Tests

```bash
pytest
# or
python manage.py test
```

---

## How It Works

### Upload Flow
1. User submits a file via the upload form.
2. A new Fernet key is generated for that file.
3. The file is encrypted chunk-by-chunk using the key.
4. The encrypted bytes are saved to disk.
5. A SHA-256 hash of the encrypted content is stored alongside the key in the database.

### Download Flow
1. The encrypted file is read from disk.
2. Its SHA-256 hash is recomputed and compared against the stored value — a mismatch raises HTTP 404.
3. The file is decrypted using the stored key.
4. The plaintext is streamed back to the user as an attachment.

### Share Flow
1. The file owner submits a username to share with.
2. A new `FileUpload` record is created for the recipient, referencing the same underlying file and key.
3. The recipient can now download and decrypt the file independently.

---

## Security Notes

- Passwords are hashed by Django's default PBKDF2 + SHA-256 hasher.
- All protected endpoints require an active authenticated session.
- The encryption scheme (Fernet) provides authenticated encryption — decryption will fail if the ciphertext is altered, in addition to the explicit SHA-256 integrity check.

