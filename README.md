# Secure Password Manager

## Scope
This project is a web-based secure password manager developed for the Web Application Security course at TalTech. It provides an encrypted digital vault for users to store, retrieve, and manage their credentials safely.

## Checkpoint 3 - Near-Final State (Week 12)
* **SQL Injection Prevention:** Exclusively uses parameterized SQLite queries (`?` placeholders) across all database operations. Verified against authentication bypass and stacked query payloads.
* **XSS Defences:** Context-aware Jinja2 auto-escaping, strict URL scheme validation (blocking `javascript:` and `data:` URIs), and strict HTTP security headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).
* **Per-User Access Control (IDOR Prevention):** Every vault read (`/vault/view/<id>`) and delete (`/vault/delete/<id>`) query enforces ownership (`WHERE id = ? AND user_id = ?`). Unauthorized cross-user attempts return HTTP `403 Forbidden` and trigger a security log alert.
* **CSRF Protection:** Cryptographic synchronizer tokens (`csrf_token`) validated via constant-time comparison (`secrets.compare_digest`) on all state-changing `POST` requests.
* **Secure Error Handling & Structured Logging:** Custom error handlers (`400`, `403`, `404`, `500`) prevent stack trace leakage. Security events are recorded in JSON-structured format inside `security.log`.

## How to Run Locally (Clean Machine Instructions)

### 1. Setup Environment

    git clone [https://github.com/HecBarLu/Web-Application-Security.git](https://github.com/HecBarLu/Web-Application-Security.git)
    cd Web-Application-Security
    python -m venv venv
    source venv/Scripts/activate
    pip install -r requirements.txt

### 2. Generate Self-Signed TLS Certificates

    unset OPENSSL_CONF
    mkdir -p certs
    MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:4096 -nodes -out certs/cert.pem -keyout certs/key.pem -days 365 -subj "/CN=localhost"

### 3. Run Automated Security Test Suite (Checkpoint 3 Evidence)

    python test_security.py

### 4. Start the Application

    python app.py

Open `[https://127.0.0.1:5000](https://127.0.0.1:5000)` in your browser.
