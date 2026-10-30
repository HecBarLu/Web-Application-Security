# Secure Password Manager

## Scope
This project is a web-based secure password manager developed for the Web Application Security course at TalTech. It provides an encrypted digital vault for users to store, retrieve, and manage their credentials safely.

## Checkpoint 2 - Progress Note (Week 9)
* Working Web Interface: Built with Flask and Jinja2 templates (login.html, register.html, vault.html) covering registration, login, credential encryption/decryption, and deletion.
* Authentication & Password Hashing: Implemented using Argon2id (argon2-cffi). Master passwords are never stored in plaintext.
* Server-Side Encryption: Vault entries are encrypted at rest using AES-256-GCM with random 12-byte IVs. The 256-bit key is derived dynamically upon login from the user's master password and a unique 16-byte salt via PBKDF2HMAC (SHA-256, 200,000 iterations).
* Secure Session Management: Configured with HttpOnly=True, Secure=True, SameSite='Strict', session regeneration upon login (to prevent session fixation), and a 15-minute idle timeout.
* TLS Setup: Served locally over HTTPS ([https://127.0.0.1:5000](https://127.0.0.1:5000)) using a 4096-bit RSA self-signed certificate.

## How to Run Locally (Clean Machine Instructions)

### Prerequisites
* Python 3.10+
* Git Bash (or any terminal with OpenSSL installed)

### Step-by-Step Execution
1. Clone the repository and enter the directory:
   git clone <YOUR_GITHUB_REPO_URL>
   cd <YOUR_REPO_FOLDER>

2. Create and activate a virtual environment:
   python -m venv venv
   source venv/Scripts/activate

3. Install the required packages:
   pip install -r requirements.txt

4. Generate the self-signed TLS certificates:
   mkdir -p certs
   MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:4096 -nodes -out certs/cert.pem -keyout certs/key.pem -days 365 -subj "/CN=localhost"

5. Start the application:
   python app.py

6. Open your browser and go to [https://127.0.0.1:5000](https://127.0.0.1:5000) (accept the self-signed certificate warning in the browser).
