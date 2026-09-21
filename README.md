# Web-Application-Security
Project for Web Application Security
# Secure Password Manager

## Scope
This project is a web-based secure password manager developed for the Web Application Security course at TalTech. It provides a secure, encrypted digital vault for users to store, retrieve, and manage their web credentials. The application is built with a "shift-left" security philosophy, designed from the ground up to mitigate OWASP Top 10 vulnerabilities, enforce strict access controls, and utilize robust cryptographic standards to protect data at rest and in transit.

## Planned Features
*   **Secure Authentication:** Strong master password hashing (e.g., Argon2id) and secure session management using `HttpOnly`, `Secure`, and `SameSite` cookies.
*   **Data-at-Rest Encryption:** Vault credentials encrypted using AES-256-GCM before database insertion.
*   **Injection Prevention:** Strict server-side input sanitization and parameterized database queries to neutralize XSS and SQL Injection risks.
*   **Error Handling:** Generic client-facing error messages to prevent stack trace and system information disclosure.

## Planned Routes
**Authentication & Sessions:**
*   `GET /` - Landing page and login interface.
*   `POST /api/auth/register` - Register a new user and generate cryptographic salts.
*   `POST /api/auth/login` - Authenticate user and issue secure session token.
*   `POST /api/auth/logout` - Invalidate and destroy the active session.

**Vault Management:**
*   `GET /vault` - User dashboard interface (protected route).
*   `GET /api/vault/items` - Fetch and decrypt the user's stored credentials.
*   `POST /api/vault/add` - Encrypt and insert a new credential into the vault.
*   `DELETE /api/vault/item/<id>` - Securely delete a credential.

## How to Run Locally (Development Setup)
*Note: These instructions outline the planned local execution flow and will be finalized in Checkpoint 2.*

### Prerequisites
*   Git
*   Python 3.10+ / Node.js (depending on the final backend framework chosen)
*   Docker & Docker Compose (recommended for isolated database provisioning)
