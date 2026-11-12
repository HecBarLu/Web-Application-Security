import os
import re
import sqlite3
import secrets
import base64
import logging
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    DB_NAME="vault.db"
)

# Configuración de Structured Security Logging (Checkpoint 3)
security_logger = logging.getLogger("SecurityAudit")
security_logger.setLevel(logging.INFO)
if not security_logger.handlers:
    file_handler = logging.FileHandler("security.log")
    formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "event": "%(message)s"}'
    )
    file_handler.setFormatter(formatter)
    security_logger.addHandler(file_handler)

ph = PasswordHasher()

def log_security_event(event_type: str, details: str, level: str = "INFO"):
    ip = request.remote_addr if request else "LOCAL"
    user = session.get('username', 'anonymous') if session else 'anonymous'
    msg = f"type={event_type} | user={user} | ip={ip} | details={details}"
    if level == "WARNING":
        security_logger.warning(msg)
    elif level == "ERROR":
        security_logger.error(msg)
    else:
        security_logger.info(msg)

def get_db_connection():
    conn = sqlite3.connect(app.config['DB_NAME'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                kdf_salt BLOB NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site_url TEXT NOT NULL,
                site_username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                iv BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

def derive_encryption_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(master_password.encode('utf-8'))

def is_safe_url(url_str: str) -> bool:
    """Valida que la URL tenga un esquema http/https válido y bloquea esquemas javascript: o data: (XSS)."""
    try:
        parsed = urlparse(url_str)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'encryption_key' not in session:
            log_security_event("UNAUTHORIZED_ACCESS_ATTEMPT", f"Unauthenticated access to {request.path}", "WARNING")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def before_request_security():
    session.permanent = True
    session.modified = True
    # Validación CSRF en todas las peticiones POST que cambian estado
    if request.method == 'POST':
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token')
        if not token or not form_token or not secrets.compare_digest(token, form_token):
            log_security_event("CSRF_VIOLATION", f"Missing or invalid CSRF token on {request.path}", "WARNING")
            return render_template('error.html', code=403, message="Forbidden: CSRF verification failed."), 403

@app.after_request
def apply_security_headers(response):
    # Defensas XSS en profundidad y cabeceras de seguridad
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# Manejadores seguros de errores (ocultan stack traces)
@app.errorhandler(400)
def bad_request_error(e):
    log_security_event("BAD_REQUEST", f"400 Bad Request on {request.path}", "WARNING")
    return render_template('error.html', code=400, message="Bad Request: Invalid parameters provided."), 400

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('error.html', code=403, message="Access Denied: You do not have permission to access this resource."), 403

@app.errorhandler(404)
def not_found_error(e):
    return render_template('error.html', code=404, message="Resource Not Found."), 404

@app.errorhandler(Exception)
def internal_server_error(e):
    log_security_event("INTERNAL_ERROR", f"Unhandled exception on {request.path}: {type(e).__name__}", "ERROR")
    return render_template('error.html', code=500, message="An unexpected internal error occurred. Please try again later."), 500

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('password', '')

        # Validación de entrada mediante lista blanca (whitelisting) y límites de longitud
        if not re.match(r'^[a-zA-Z0-9_.-]{3,32}$', username) or len(master_password) < 8 or len(master_password) > 128:
            log_security_event("REGISTER_VALIDATION_FAILED", f"Invalid username or password format for '{username}'", "WARNING")
            flash("Invalid input. Username must be 3-32 alphanumeric characters and password 8-128 characters.")
            return redirect(url_for('register'))

        password_hash = ph.hash(master_password)
        kdf_salt = os.urandom(16)

        try:
            with get_db_connection() as conn:
                conn.execute(
                    'INSERT INTO users (username, password_hash, kdf_salt) VALUES (?, ?, ?)',
                    (username, password_hash, kdf_salt)
                )
                conn.commit()
            log_security_event("USER_REGISTERED", f"New user '{username}' registered successfully")
            flash("Registration successful! Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            log_security_event("REGISTER_CONFLICT", f"Attempted registration with existing username '{username}'", "WARNING")
            flash("Username already exists.")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('password', '')

        with get_db_connection() as conn:
            # Consulta parametrizada contra SQL Injection
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            try:
                ph.verify(user['password_hash'], master_password)
                session.clear()
                enc_key = derive_encryption_key(master_password, user['kdf_salt'])
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['encryption_key'] = base64.b64encode(enc_key).decode('utf-8')
                session['csrf_token'] = secrets.token_hex(32)
                log_security_event("LOGIN_SUCCESS", f"User '{username}' authenticated successfully")
                return redirect(url_for('vault'))
            except VerifyMismatchError:
                pass
        
        log_security_event("LOGIN_FAILED", f"Failed authentication attempt for username '{username}'", "WARNING")
        flash("Invalid username or master password.")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    log_security_event("USER_LOGOUT", "User logged out and session destroyed")
    session.clear()
    flash("You have been logged out securely.")
    return redirect(url_for('login'))

@app.route('/vault')
@login_required
def vault():
    user_id = session['user_id']
    enc_key = base64.b64decode(session['encryption_key'])
    aesgcm = AESGCM(enc_key)

    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM vault WHERE user_id = ?', (user_id,)).fetchall()

    decrypted_items = []
    for row in rows:
        try:
            decrypted_bytes = aesgcm.decrypt(row['iv'], row['encrypted_password'], None)
            decrypted_password = decrypted_bytes.decode('utf-8')
        except Exception:
            log_security_event("CRYPTO_INTEGRITY_ERROR", f"AES-GCM tag verification failed for item_id={row['id']}", "ERROR")
            decrypted_password = "[Decryption Error / Corrupted Data]"

        decrypted_items.append({
            'id': row['id'],
            'site_url': row['site_url'],
            'site_username': row['site_username'],
            'password': decrypted_password
        })

    return render_template('vault.html', items=decrypted_items, username=session['username'])

@app.route('/vault/view/<int:item_id>', methods=['GET'])
@login_required
def view_credential(item_id):
    """Endpoint para verificar el control de acceso por usuario (prevención de IDOR)."""
    with get_db_connection() as conn:
        row = conn.execute(
            'SELECT * FROM vault WHERE id = ? AND user_id = ?',
            (item_id, session['user_id'])
        ).fetchone()

    if not row:
        log_security_event(
            "IDOR_READ_BLOCKED",
            f"User id={session['user_id']} attempted unauthorized read on vault item_id={item_id}",
            "WARNING"
        )
        return render_template('error.html', code=403, message="Forbidden: You are not authorized to view this vault entry."), 403

    enc_key = base64.b64decode(session['encryption_key'])
    aesgcm = AESGCM(enc_key)
    decrypted_password = aesgcm.decrypt(row['iv'], row['encrypted_password'], None).decode('utf-8')
    log_security_event("VAULT_ITEM_READ", f"User accessed vault item_id={item_id}")

    return jsonify({
        "id": row["id"],
        "site_url": row["site_url"],
        "site_username": row["site_username"],
        "password": decrypted_password
    }), 200

@app.route('/vault/add', methods=['POST'])
@login_required
def add_credential():
    site_url = request.form.get('site_url', '').strip()
    site_username = request.form.get('site_username', '').strip()
    plain_password = request.form.get('password', '')

    if not site_url or not site_username or not plain_password:
        flash("All fields are required.")
        return redirect(url_for('vault'))

    if len(site_url) > 255 or len(site_username) > 128 or len(plain_password) > 256:
        log_security_event("INPUT_LIMIT_EXCEEDED", "Vault entry exceeded maximum length constraints", "WARNING")
        flash("Input exceeds maximum allowed length.")
        return redirect(url_for('vault'))

    if not is_safe_url(site_url):
        log_security_event("UNSAFE_URL_BLOCKED", f"Blocked potentially malicious URL scheme: {site_url}", "WARNING")
        flash("Invalid URL format. Only http:// and https:// URLs are permitted.")
        return redirect(url_for('vault'))

    enc_key = base64.b64decode(session['encryption_key'])
    aesgcm = AESGCM(enc_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plain_password.encode('utf-8'), None)

    with get_db_connection() as conn:
        conn.execute(
            'INSERT INTO vault (user_id, site_url, site_username, encrypted_password, iv) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], site_url, site_username, ciphertext, iv)
        )
        conn.commit()

    log_security_event("VAULT_ITEM_ADDED", f"Added encrypted credential for {site_url}")
    flash("Credential encrypted and added to vault.")
    return redirect(url_for('vault'))

@app.route('/vault/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_credential(item_id):
    with get_db_connection() as conn:
        cursor = conn.execute(
            'DELETE FROM vault WHERE id = ? AND user_id = ?',
            (item_id, session['user_id'])
        )
        conn.commit()

    if cursor.rowcount == 0:
        log_security_event(
            "IDOR_DELETE_BLOCKED",
            f"User id={session['user_id']} attempted unauthorized deletion of vault item_id={item_id}",
            "WARNING"
        )
        return render_template('error.html', code=403, message="Forbidden: You cannot delete another user's vault entry."), 403

    log_security_event("VAULT_ITEM_DELETED", f"Deleted vault item_id={item_id}")
    flash("Credential removed.")
    return redirect(url_for('vault'))

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, ssl_context=('certs/cert.pem', 'certs/key.pem'), debug=False)
