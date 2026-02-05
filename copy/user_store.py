import json
import os
import time
import base64
import logging
import hmac
import hashlib
from pathlib import Path
from collections import defaultdict
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

class UserStore:
    """
    Handles user database, authentication, and security.
    """

    def __init__(self):
        # Define directories and files
        self.config_dir = Path.home() / '.secure_messenger'
        self.keys_dir = self.config_dir / 'keys'
        self.logs_dir = self.config_dir / 'logs'
        self.users_file = self.config_dir / 'users.json'

        # Create necessary directories
        self._initialize_directories()
        
        # Setup logging first, before loading the database
        self._setup_logging()
        
        # Load user database
        self.users_db = self._load_users_db()
        
        # Rate limiting and account lockout
        self.login_attempts = defaultdict(list)  # username -> [timestamp, timestamp, ...]
        self.locked_accounts = {}  # username -> unlock_timestamp
        self.MAX_LOGIN_ATTEMPTS = 5
        self.LOCKOUT_DURATION = 900  # 15 minutes in seconds
        self.RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds
        
        # Challenge-response authentication
        self.active_challenges = {}  # username -> {nonce, timestamp}
        self.CHALLENGE_TIMEOUT = 300  # 5 minutes

    def _initialize_directories(self):
        """Create configuration, keys, and logs directories."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        if os.name != 'nt':  # Set restrictive permissions on Unix systems
            os.chmod(self.config_dir, 0o700)
            os.chmod(self.keys_dir, 0o700)

    def _setup_logging(self):
        """Setup security logging."""
        self.logger = logging.getLogger('UserStore')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.logs_dir / 'security.log', encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _load_users_db(self):
        """Load the user database from the JSON file."""
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load user database: {e}")
                # If the file exists but is empty or corrupted, return an empty dict
                return {}
        return {}

    def _save_users_db(self):
        """Save the user database to the JSON file."""
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(self.users_db, f, indent=4)
            if os.name != 'nt':
                os.chmod(self.users_file, 0o600)
        except Exception as e:
            self.logger.error(f"Failed to save user database: {e}")

    def _hash_password(self, password, salt=None):
        """Hash a password using PBKDF2 with SHA-256."""
        if salt is None:
            salt = get_random_bytes(32)
        key = PBKDF2(password.encode('utf-8'), salt, 32, count=100000, hmac_hash_module=SHA256)
        return salt + key

    def _verify_password(self, password, stored_hash):
        """Verify a password against a stored hash."""
        try:
            stored_bytes = base64.b64decode(stored_hash)
            salt, stored_key = stored_bytes[:32], stored_bytes[32:]
            calculated_key = PBKDF2(password.encode('utf-8'), salt, 32, count=100000, hmac_hash_module=SHA256)
            return calculated_key == stored_key
        except Exception as e:
            self.logger.error(f"Password verification failed: {e}")
            return False

    def _generate_rsa_keypair(self):
        """Generate a new RSA key pair."""
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()
        public_key = rsa_key.publickey().export_key()
        return private_key, public_key

    def create_user(self, username, password):
        """Create a new user account."""
        if username in self.users_db:
            return False, "Username already exists."

        private_key, public_key = self._generate_rsa_keypair()
        password_hash = self._hash_password(password)

        self.users_db[username] = {
            'password_hash': base64.b64encode(password_hash).decode('utf-8'),
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'created_at': int(time.time()),
            'last_login': None
        }

        self._save_users_db()
        self._save_private_key(username, private_key, password)
        self.logger.info(f"User created: {username}")
        return True, "User created successfully."

    def create_user_with_pubkey(self, username, password, pubkey_bytes):
        """Create a new user account with a client-provided public key."""
        if username in self.users_db:
            return False, "Username already exists."

        password_hash = self._hash_password(password)

        self.users_db[username] = {
            'password_hash': base64.b64encode(password_hash).decode('utf-8'),
            'public_key': base64.b64encode(pubkey_bytes).decode('utf-8'),
            'created_at': int(time.time()),
            'last_login': None
        }

        self._save_users_db()
        self.logger.info(f"User created with client pubkey: {username}")
        return True, "User created successfully."

    def _is_account_locked(self, username):
        """Check if an account is currently locked."""
        if username in self.locked_accounts:
            unlock_time = self.locked_accounts[username]
            if time.time() < unlock_time:
                remaining = int(unlock_time - time.time())
                return True, remaining
            else:
                # Unlock expired, remove from locked accounts
                del self.locked_accounts[username]
                self.login_attempts[username] = []
        return False, 0

    def _record_failed_login(self, username, ip_address=None):
        """Record a failed login attempt and lock account if threshold exceeded."""
        current_time = time.time()
        
        # Clean old attempts outside the rate limit window
        self.login_attempts[username] = [
            t for t in self.login_attempts[username]
            if current_time - t < self.RATE_LIMIT_WINDOW
        ]
        
        # Add current failed attempt
        self.login_attempts[username].append(current_time)
        
        # Check if we should lock the account
        if len(self.login_attempts[username]) >= self.MAX_LOGIN_ATTEMPTS:
            unlock_time = current_time + self.LOCKOUT_DURATION
            self.locked_accounts[username] = unlock_time
            self.logger.warning(
                f"Account locked due to {self.MAX_LOGIN_ATTEMPTS} failed attempts: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            return True
        
        return False

    def _clear_login_attempts(self, username):
        """Clear login attempts for a user after successful login."""
        if username in self.login_attempts:
            del self.login_attempts[username]
        if username in self.locked_accounts:
            del self.locked_accounts[username]

    def create_challenge(self, username):
        """Create authentication challenge for a user."""
        # Generate cryptographically secure random nonce
        nonce = base64.b64encode(get_random_bytes(32)).decode('utf-8')
        
        # Get the salt from the stored password hash
        user = self.users_db.get(username)
        if not user:
            return None, None
        
        stored_hash = user['password_hash']
        stored_bytes = base64.b64decode(stored_hash)
        salt = stored_bytes[:32]  # Extract the salt
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        
        self.active_challenges[username] = {
            'nonce': nonce,
            'salt': salt_b64,
            'timestamp': time.time()
        }
        
        self.logger.info(f"Authentication challenge created for user: {username}")
        return nonce, salt_b64  # Return both nonce and salt

    def verify_challenge_response(self, username, response, ip_address=None):
        """Verify challenge-response authentication."""
        # Check if account is locked
        is_locked, remaining = self._is_account_locked(username)
        if is_locked:
            self.logger.warning(
                f"Login attempt for locked account: {username} "
                f"(IP: {ip_address or 'unknown'}, {remaining}s remaining)"
            )
            return False, f"Account locked. Try again in {remaining} seconds."

        # Check if user exists
        user = self.users_db.get(username)
        if not user:
            self.logger.warning(
                f"Authentication failed for non-existent user: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            # Constant-time response to prevent username enumeration
            time.sleep(0.5)
            return False, "Invalid username or password."

        # Check if challenge exists and is valid
        challenge = self.active_challenges.get(username)
        if not challenge:
            self.logger.warning(
                f"No active challenge for user: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            return False, "Authentication session expired. Please try again."

        # Check if challenge has expired
        if time.time() - challenge['timestamp'] > self.CHALLENGE_TIMEOUT:
            del self.active_challenges[username]
            self.logger.warning(
                f"Expired challenge for user: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            return False, "Authentication session expired. Please try again."

        # Verify the response
        try:
            # Get stored password hash
            stored_hash = user['password_hash']
            stored_bytes = base64.b64decode(stored_hash)
            salt = stored_bytes[:32]
            stored_key = stored_bytes[32:]
            
            # Compute expected response: HMAC-SHA256(password_key, nonce)
            nonce_bytes = challenge['nonce'].encode('utf-8')
            expected_response = hmac.new(stored_key, nonce_bytes, hashlib.sha256).digest()
            expected_response_b64 = base64.b64encode(expected_response).decode('utf-8')
            
            # Constant-time comparison
            if not hmac.compare_digest(response, expected_response_b64):
                self.logger.warning(
                    f"Authentication failed - invalid response: {username} "
                    f"(IP: {ip_address or 'unknown'})"
                )
                
                # Record failed attempt
                locked = self._record_failed_login(username, ip_address)
                if locked:
                    return False, f"Account locked due to too many failed attempts. Try again in {self.LOCKOUT_DURATION // 60} minutes."
                
                attempts_left = self.MAX_LOGIN_ATTEMPTS - len(self.login_attempts[username])
                return False, f"Invalid username or password. {attempts_left} attempts remaining."

            # Success! Clear the challenge
            del self.active_challenges[username]
            
            # Clear failed login attempts
            self._clear_login_attempts(username)
            
            # Update last login
            self.users_db[username]['last_login'] = int(time.time())
            self._save_users_db()
            
            self.logger.info(
                f"User authenticated successfully: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            return True, "Authentication successful."
            
        except Exception as e:
            self.logger.error(f"Challenge verification error for {username}: {e}")
            return False, "Authentication error. Please try again."

    def authenticate_user(self, username, password, ip_address=None):
        """Legacy authentication - DEPRECATED. Use challenge-response instead."""
        self.logger.warning(f"Legacy password authentication used for: {username}")
        # Check if account is locked
        is_locked, remaining = self._is_account_locked(username)
        if is_locked:
            self.logger.warning(
                f"Login attempt for locked account: {username} "
                f"(IP: {ip_address or 'unknown'}, {remaining}s remaining)"
            )
            return False, f"Account locked. Try again in {remaining} seconds."

        user = self.users_db.get(username)
        if not user:
            self.logger.warning(
                f"Authentication failed for non-existent user: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            # Still record failed attempt to prevent username enumeration timing attacks
            time.sleep(0.5)  # Constant-time response
            return False, "Invalid username or password."

        if not self._verify_password(password, user['password_hash']):
            self.logger.warning(
                f"Authentication failed - wrong password: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            
            # Record failed attempt
            locked = self._record_failed_login(username, ip_address)
            if locked:
                return False, f"Account locked due to too many failed attempts. Try again in {self.LOCKOUT_DURATION // 60} minutes."
            
            attempts_left = self.MAX_LOGIN_ATTEMPTS - len(self.login_attempts[username])
            return False, f"Invalid username or password. {attempts_left} attempts remaining."

        # Successful authentication
        self._clear_login_attempts(username)
        self.users_db[username]['last_login'] = int(time.time())
        self._save_users_db()
        self.logger.info(
            f"User authenticated successfully: {username} "
            f"(IP: {ip_address or 'unknown'})"
        )
        return True, "Authentication successful."

    def _save_private_key(self, username, private_key, password):
        """Save the user's private key encrypted with their password."""
        salt = get_random_bytes(16)
        encryption_key = PBKDF2(password.encode('utf-8'), salt, 32, count=100000, hmac_hash_module=SHA256)
        cipher = AES.new(encryption_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)

        key_file = self.keys_dir / f"{username}_private.key"
        with open(key_file, 'wb') as f:
            f.write(salt + cipher.nonce + tag + ciphertext)

        if os.name != 'nt':
            os.chmod(key_file, 0o600)

    def load_private_key(self, username, password):
        """Load and decrypt the user's private key."""
        key_file = self.keys_dir / f"{username}_private.key"
        if not key_file.exists():
            self.logger.error(f"Private key file not found for user: {username}")
            return None

        try:
            with open(key_file, 'rb') as f:
                data = f.read()
                salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]

            encryption_key = PBKDF2(password.encode('utf-8'), salt, 32, count=100000, hmac_hash_module=SHA256)
            cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
            private_key = cipher.decrypt_and_verify(ciphertext, tag)
            return RSA.import_key(private_key)
        except Exception as e:
            self.logger.error(f"Failed to load private key for user {username}: {e}")
            return None