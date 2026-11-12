import os
import re
import unittest
from app import app, init_db, get_db_connection

class SecurityVerificationTestSuite(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_vault.db"
        app.config['TESTING'] = True
        app.config['DB_NAME'] = self.test_db
        self.client = app.test_client()
        with app.app_context():
            init_db()

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def _get_csrf(self, path='/login'):
        res = self.client.get(path)
        match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', res.data.decode('utf-8'))
        return match.group(1) if match else ""

    def _register_and_login(self, username, password):
        csrf = self._get_csrf('/register')
        self.client.post('/register', data={'username': username, 'password': password, 'csrf_token': csrf}, follow_redirects=True)
        csrf = self._get_csrf('/login')
        return self.client.post('/login', data={'username': username, 'password': password, 'csrf_token': csrf}, follow_redirects=True)

    def test_01_sql_injection_mitigation(self):
        """TC-01: Verify SQL Injection payloads fail to bypass authentication or corrupt database."""
        self._register_and_login("alice", "StrongPass123!")
        self.client.post('/logout', data={'csrf_token': self._get_csrf('/vault')})

        sqli_payloads = [
            "' OR '1'='1' --",
            "alice' --",
            "admin' OR 1=1#",
            "'; DROP TABLE users; --"
        ]
        for payload in sqli_payloads:
            csrf = self._get_csrf('/login')
            res = self.client.post('/login', data={
                'username': payload,
                'password': 'randompassword',
                'csrf_token': csrf
            }, follow_redirects=True)
            self.assertIn(b"Invalid username or master password.", res.data)
            self.assertNotIn(b"Encrypted Vault", res.data)

    def test_02_xss_defense_and_scheme_validation(self):
        """TC-02: Verify Stored XSS payloads are HTML-encoded and javascript: URLs are rejected."""
        self._register_and_login("alice", "StrongPass123!")
        csrf = self._get_csrf('/vault')

        # Intento 1: Stored XSS en el campo site_username
        xss_payload = "<script>alert(document.cookie)</script>"
        res = self.client.post('/vault/add', data={
            'site_url': 'https://example.com',
            'site_username': xss_payload,
            'password': 'SecretPassword1!',
            'csrf_token': csrf
        }, follow_redirects=True)

        body = res.data.decode('utf-8')
        self.assertNotIn("<script>alert(document.cookie)</script>", body)
        self.assertIn("<script>alert(document.cookie)</script>", body)
        self.assertIn("Content-Security-Policy", res.headers)

        # Intento 2: XSS mediante esquema javascript: en el campo site_url
        csrf = self._get_csrf('/vault')
        res_js_url = self.client.post('/vault/add', data={
            'site_url': 'javascript:alert(document.domain)',
            'site_username': 'victim_user',
            'password': 'SecretPassword1!',
            'csrf_token': csrf
        }, follow_redirects=True)
        self.assertIn(b"Invalid URL format. Only http:// and https:// URLs are permitted.", res_js_url.data)

    def test_03_per_user_access_control_idor_prevention(self):
        """TC-03: Verify User B cannot read or delete User A's vault entry (IDOR Prevention)."""
        # Alice crea una credencial (ID = 1)
        self._register_and_login("alice", "AliceMasterPass123!")
        csrf_alice = self._get_csrf('/vault')
        self.client.post('/vault/add', data={
            'site_url': 'https://bank.example.com',
            'site_username': 'alice_bank',
            'password': 'AliceTopSecretPassword',
            'csrf_token': csrf_alice
        }, follow_redirects=True)
        self.client.post('/logout', data={'csrf_token': self._get_csrf('/vault')})

        # Bob se registra e intenta leer y borrar el item #1 de Alice
        self._register_and_login("bob_attacker", "BobMasterPass123!")
        
        # Intento de lectura cruzada (GET /vault/view/1)
        read_res = self.client.get('/vault/view/1')
        self.assertEqual(read_res.status_code, 403)
        self.assertNotIn(b"AliceTopSecretPassword", read_res.data)

        # Intento de borrado cruzado (POST /vault/delete/1)
        csrf_bob = self._get_csrf('/vault')
        del_res = self.client.post('/vault/delete/1', data={'csrf_token': csrf_bob})
        self.assertEqual(del_res.status_code, 403)

    def test_04_csrf_protection_enforcement(self):
        """TC-04: Verify state-changing POST requests without valid CSRF token are blocked with 403."""
        self._register_and_login("alice", "AliceMasterPass123!")
        res = self.client.post('/vault/add', data={
            'site_url': 'https://evil.com',
            'site_username': 'attacker',
            'password': 'hacked',
            'csrf_token': 'forged_invalid_token_0000'
        })
        self.assertEqual(res.status_code, 403)
        self.assertIn(b"CSRF verification failed", res.data)

    def test_05_secure_error_handling_and_logging(self):
        """TC-05: Verify errors do not leak stack traces and security events are logged."""
        res = self.client.get('/non_existent_route_12345')
        self.assertEqual(res.status_code, 404)
        self.assertIn(b"Resource Not Found", res.data)
        self.assertNotIn(b"Traceback", res.data)
        self.assertTrue(os.path.exists("security.log"))

if __name__ == '__main__':
    unittest.main(verbosity=2)
