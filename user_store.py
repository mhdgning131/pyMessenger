import json
import os
import time
import base64
import re
import logging
import hmac
import hashlib
from copy import deepcopy
from pathlib import Path
from collections import defaultdict
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

class UserStore:

    def __init__(self):
        self.config_dir = Path.home() / '.secure_messenger'
        self.keys_dir = self.config_dir / 'keys'
        self.logs_dir = self.config_dir / 'logs'
        self.users_file = self.config_dir / 'users.json'

        self._initialize_directories()
        
        self._setup_logging()
        
        self.users_db = self._load_users_db()
        
        self.login_attempts = defaultdict(list)                                           
        self.locked_accounts = {}                                
        self.MAX_LOGIN_ATTEMPTS = 5
        self.LOCKOUT_DURATION = 900                         
        self.RATE_LIMIT_WINDOW = 300                        
        
        self.active_challenges = {}                                  
        self.CHALLENGE_TIMEOUT = 300             

    def _initialize_directories(self):
                                                               
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        if os.name != 'nt':                                               
            os.chmod(self.config_dir, 0o700)
            os.chmod(self.keys_dir, 0o700)

    def _setup_logging(self):
                                     
        self.logger = logging.getLogger('UserStore')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.logs_dir / 'security.log', encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _load_users_db(self):
                                                        
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to load user database: {e}")
                                                                                    
                return {}
        return {}

    def _save_users_db(self):
                                                      
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                json.dump(self.users_db, f, indent=4)
            if os.name != 'nt':
                os.chmod(self.users_file, 0o600)
        except Exception as e:
            self.logger.error(f"Failed to save user database: {e}")

    def _is_valid_username(self, username):
                                                                              
        if not isinstance(username, str):
            return False

        return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9])?", username))

    def _hash_password(self, password, salt=None):
                                                        
        if salt is None:
            salt = get_random_bytes(32)
        key = PBKDF2(password.encode('utf-8'), salt, 32, count=100000, hmac_hash_module=SHA256)
        return salt + key



    def create_user_with_pubkey(self, username, password, pubkey_bytes):
                                                                          
        if not self._is_valid_username(username):
            return False, "Invalid username. Use 1-64 characters: letters, numbers, dot, underscore, or hyphen."

        if username in self.users_db:
            return False, "Username already exists."

        password_hash = self._hash_password(password)

        self.users_db[username] = {
            'password_hash': base64.b64encode(password_hash).decode('utf-8'),
            'public_key': base64.b64encode(pubkey_bytes).decode('utf-8'),
            'created_at': int(time.time()),
            'last_login': None,
            'signal_bundle': None,
            'signal_bundle_updated_at': None
        }

        self._save_users_db()
        self.logger.info(f"User created with client pubkey: {username}")
        return True, "User created successfully."

    def _is_account_locked(self, username):
                                                      
        if username in self.locked_accounts:
            unlock_time = self.locked_accounts[username]
            if time.time() < unlock_time:
                remaining = int(unlock_time - time.time())
                return True, remaining
            else:
                                                             
                del self.locked_accounts[username]
                self.login_attempts[username] = []
        return False, 0

    def _record_failed_login(self, username, ip_address=None):
                                                                                   
        current_time = time.time()
        
                                                          
        self.login_attempts[username] = [
            t for t in self.login_attempts[username]
            if current_time - t < self.RATE_LIMIT_WINDOW
        ]
        
                                    
        self.login_attempts[username].append(current_time)
        
                                             
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
                                                                     
        if username in self.login_attempts:
            del self.login_attempts[username]
        if username in self.locked_accounts:
            del self.locked_accounts[username]

    def create_challenge(self, username):
                                                         
                                                        
        nonce = base64.b64encode(get_random_bytes(32)).decode('utf-8')
        
                                                    
        user = self.users_db.get(username)
        if not user:
            return None, None
        
        stored_hash = user['password_hash']
        stored_bytes = base64.b64decode(stored_hash)
        salt = stored_bytes[:32]                    
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        
        self.active_challenges[username] = {
            'nonce': nonce,
            'salt': salt_b64,
            'timestamp': time.time()
        }
        
        self.logger.info(f"Authentication challenge created for user: {username}")
        return nonce, salt_b64                              

    def verify_challenge_response(self, username, response, ip_address=None):
                                                       
                                    
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
                                                                    
            time.sleep(0.5)
            return False, "Invalid username or password."

                                                
        challenge = self.active_challenges.get(username)
        if not challenge:
            self.logger.warning(
                f"No active challenge for user: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            return False, "Authentication session expired. Please try again."

                                        
        if time.time() - challenge['timestamp'] > self.CHALLENGE_TIMEOUT:
            del self.active_challenges[username]
            self.logger.warning(
                f"Expired challenge for user: {username} "
                f"(IP: {ip_address or 'unknown'})"
            )
            return False, "Authentication session expired. Please try again."

                             
        try:
                                      
            stored_hash = user['password_hash']
            stored_bytes = base64.b64decode(stored_hash)
            salt = stored_bytes[:32]
            stored_key = stored_bytes[32:]
            
                                                                         
            nonce_bytes = challenge['nonce'].encode('utf-8')
            expected_response = hmac.new(stored_key, nonce_bytes, hashlib.sha256).digest()
            expected_response_b64 = base64.b64encode(expected_response).decode('utf-8')
            
                                      
            if not hmac.compare_digest(response, expected_response_b64):
                self.logger.warning(
                    f"Authentication failed - invalid response: {username} "
                    f"(IP: {ip_address or 'unknown'})"
                )
                
                                       
                locked = self._record_failed_login(username, ip_address)
                if locked:
                    return False, f"Account locked due to too many failed attempts. Try again in {self.LOCKOUT_DURATION // 60} minutes."
                
                attempts_left = self.MAX_LOGIN_ATTEMPTS - len(self.login_attempts[username])
                return False, f"Invalid username or password. {attempts_left} attempts remaining."

                                          
            del self.active_challenges[username]
            
                                         
            self._clear_login_attempts(username)
            
                               
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



    def load_private_key(self, username, password):
                                                      
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

    def set_signal_bundle(self, username, bundle):
                                                            
        user = self.users_db.get(username)
        if not user:
            return False, "User not found."

        if not bundle or not isinstance(bundle, dict):
            return False, "Invalid Signal bundle."

        required_fields = ['identity_sign_pub', 'identity_dh_pub', 'signed_prekey_pub', 'signed_prekey_signature']
        for field_name in required_fields:
            if not bundle.get(field_name):
                return False, f"Missing Signal bundle field: {field_name}"

        user['signal_bundle'] = bundle
        user['signal_bundle_updated_at'] = int(time.time())
        self._save_users_db()
        return True, "Signal bundle stored."

    def get_signal_bundle(self, username, consume_one_time=True):
                                                                                                  
        user = self.users_db.get(username)
        if not user:
            return None

        bundle = user.get('signal_bundle')
        if not bundle:
            return None

        bundle_copy = deepcopy(bundle)

        if consume_one_time:
            one_time_prekeys = list(user['signal_bundle'].get('one_time_prekeys') or [])
            if one_time_prekeys:
                one_time_prekeys.pop(0)
                user['signal_bundle']['one_time_prekeys'] = one_time_prekeys
                user['signal_bundle_updated_at'] = int(time.time())
                self._save_users_db()
                bundle_copy['one_time_prekeys'] = deepcopy(one_time_prekeys)

        return bundle_copy

    def has_signal_bundle(self, username):
                                                                
        user = self.users_db.get(username)
        return bool(user and user.get('signal_bundle'))