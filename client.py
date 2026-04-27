import socket
import threading
import json
import base64
import hashlib
import struct
import getpass
import os
import sys
import argparse
import ssl
import secrets
from pathlib import Path
from datetime import datetime
from collections import deque

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from signal_protocol import (
    SignalKeyStore,
    SignalKeyMaterial,
    SignalPeerBundle,
    SignalSession,
    create_initiator_session,
    accept_session_init,
    encrypt_session_message,
)

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import HTML, ANSI
from prompt_toolkit.styles import Style

RED = "\033[91;1m"
GREEN = "\033[92;1m"
BLUE = "\033[94;1m"
YELLOW = "\033[93;1m"
CYAN = "\033[96;1m"
MAGENTA = "\033[95;1m"
WHITE = "\033[97;1m"
GRAY = "\033[90;1m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

BOX_TL = "╔"
BOX_TR = "╗"
BOX_BL = "╚"
BOX_BR = "╝"
BOX_H = "═"
BOX_V = "║"
ARROW = "→"
BULLET = "•"
CHECKMARK = "✓"
X_MARK = "✗"

def send_json(sock, obj):
                                       
    data = json.dumps(obj).encode('utf-8')
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)

def recv_json(sock):
                                          
    header = b''
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    length = struct.unpack('>I', header)[0]
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))
        if not chunk:
            return None
        data += chunk
    try:
        return json.loads(data.decode('utf-8'))
    except Exception:
        return None


def safe_path_component(value, fallback='item'):
                                                                                  
    text = Path(str(value)).name
    safe = ''.join(ch for ch in text if ch.isalnum() or ch in ('-', '_', '.'))
    safe = safe.strip(' ._-')

    if not safe:
        safe = fallback

    if safe.lower() in {'con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'}:
        safe = f'_{safe}'

    return safe


class KeyManager:
                                                   
    
    def __init__(self):
        self.config_dir = Path.home() / '.secure_messenger_client'
        self.keys_dir = self.config_dir / 'keys'
        self.files_dir = self.config_dir / 'files'
        self.received_dir = self.files_dir / 'received'
        self.sent_dir = self.files_dir / 'sent'
        self._initialize_directories()
    
    def _initialize_directories(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.received_dir.mkdir(parents=True, exist_ok=True)
        self.sent_dir.mkdir(parents=True, exist_ok=True)
        if os.name != 'nt':
            os.chmod(self.config_dir, 0o700)
            os.chmod(self.keys_dir, 0o700)
            os.chmod(self.files_dir, 0o700)
    
    def _derive_key(self, password, salt):
        return PBKDF2(
            password.encode('utf-8'),
            salt,
            32,
            count=600000,
            hmac_hash_module=SHA256
        )
    
    def save_private_key(self, username, private_key, password):
                                                 
        safe_username = safe_path_component(username, 'user')
        salt = get_random_bytes(16)
        encryption_key = self._derive_key(password, salt)
        cipher = AES.new(encryption_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        
        key_file = self.keys_dir / f"{safe_username}_private.key"
        with open(key_file, 'wb') as f:
            f.write(salt + cipher.nonce + tag + ciphertext)
        
        if os.name != 'nt':
            os.chmod(key_file, 0o600)
    
    def load_private_key(self, username, password):
                                                     
        safe_username = safe_path_component(username, 'user')
        key_file = self.keys_dir / f"{safe_username}_private.key"
        if not key_file.exists():
            return None
        
        try:
            with open(key_file, 'rb') as f:
                data = f.read()
                salt = data[:16]
                nonce = data[16:32]
                tag = data[32:48]
                ciphertext = data[48:]
            
            encryption_key = self._derive_key(password, salt)
            cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
            private_key = cipher.decrypt_and_verify(ciphertext, tag)
            return RSA.import_key(private_key)
        except Exception:
            return None
    
    def key_exists(self, username):
                                                      
        safe_username = safe_path_component(username, 'user')
        key_file = self.keys_dir / f"{safe_username}_private.key"
        return key_file.exists()

class Client:
    def __init__(self, host='3.73.36.161', port=80, ca_cert_path=None):
        self.host = host
        self.port = port
        self.client_socket = None
        self.running = False
        self.peer_keys = {}
        self.key_manager = KeyManager()
        self.signal_store = SignalKeyStore()
        self.ca_cert_path = Path(ca_cert_path).expanduser() if ca_cert_path else Path.home() / '.secure_messenger' / 'certs' / 'ca.crt'
        
        self.username = None
        self.rsa_key = None
        self.session_token = None
        self.signal_material = None
        self.signal_sessions = {}
        
                                                   
        self.message_history = deque(maxlen=100)
        self.history_lock = threading.Lock()
        
                                                  
        self.prompt_session = None
        
                                                              
        self.current_room = None
        
                                 
        self.pending_invite = None                                       
        self.invite_lock = threading.Lock()

                                                                     
        self.pending_requests = {}
        self.pending_requests_lock = threading.Lock()
        
                                
        self.pending_file_offers = {}                                                                   
        self.active_file_transfers = {}                                                                         
        self.pending_file_sends = {}                                                      
        self.file_lock = threading.Lock()
        self._remote_peer_fingerprint = None
        
                       
        self.ssl_context = self._setup_ssl()

    def _is_local_host(self):
                                                                          
        host = str(self.host).strip().lower()
        return host in {'localhost', '127.0.0.1', '::1'}

    def _origin_file(self):
                                                                                     
        return self.ca_cert_path.with_name(self.ca_cert_path.name + '.origin')

    def _load_trust_origin(self):
                                                                         
        try:
            origin_file = self._origin_file()
            if not origin_file.exists():
                return None

            origin = origin_file.read_text(encoding='utf-8').strip()
            parts = origin.split()
            if len(parts) == 3 and parts[0] == 'pinned-remote' and parts[1] == f'{self.host}:{self.port}':
                return parts[2]
            return None
        except Exception:
            return None

    def _certificate_fingerprint(self, pem_text):
                                                                         
        der_bytes = ssl.PEM_cert_to_DER_cert(pem_text)
        return hashlib.sha256(der_bytes).hexdigest()

    def _bootstrap_remote_certificate(self, ca_cert_file):
                                                                                           
        try:
            print(f"{YELLOW}! No local CA certificate found; pinning the remote server certificate from {self.host}:{self.port}{RESET}")
            server_cert_pem = ssl.get_server_certificate((self.host, self.port))
            ca_cert_file.parent.mkdir(parents=True, exist_ok=True)
            ca_cert_file.write_text(server_cert_pem, encoding='utf-8')

            fingerprint = self._certificate_fingerprint(server_cert_pem)

            origin_file = self._origin_file()
            origin_file.write_text(f'pinned-remote {self.host}:{self.port} {fingerprint}\n', encoding='utf-8')

            if os.name != 'nt':
                os.chmod(ca_cert_file, 0o644)
                os.chmod(origin_file, 0o600)

            self._remote_peer_fingerprint = fingerprint
            print(f"{GREEN}✓ Server certificate pinned to {ca_cert_file}{RESET}")
            return True
        except Exception as e:
            print(f"{RED}✗ Failed to pin the remote server certificate: {e}{RESET}")
            return False

    def _setup_ssl(self):
                                                           
        try:
                                           
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            
                                                           
            ca_cert_file = self.ca_cert_path
            saved_fingerprint = self._load_trust_origin()

            if not ca_cert_file.exists() and self._is_local_host():
                try:
                    from generate_certificates import ensure_certificates
                    ensure_certificates(ca_cert_file.parent)
                except Exception as e:
                    print(f"{RED}✗ Failed to generate local TLS certificates: {e}{RESET}")

            if not ca_cert_file.exists() and not self._is_local_host():
                if not self._bootstrap_remote_certificate(ca_cert_file):
                    print(f"{YELLOW}! Copy the server's ca.crt to that path or pass --ca-cert{RESET}")
                    return None

            if not self._is_local_host() and self._remote_peer_fingerprint is None:
                if ca_cert_file.exists():
                    try:
                        pinned_pem = ca_cert_file.read_text(encoding='utf-8')
                        self._remote_peer_fingerprint = self._certificate_fingerprint(pinned_pem)
                    except Exception as e:
                        print(f"{RED}✗ Invalid pinned certificate at {ca_cert_file}: {e}{RESET}")
                        return None
                elif saved_fingerprint:
                    self._remote_peer_fingerprint = saved_fingerprint
            
            if ca_cert_file.exists():
                if self._is_local_host():
                    context.load_verify_locations(cafile=str(ca_cert_file))
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                    print(f"{GREEN}✓ Root CA loaded for server validation{RESET}")
                else:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    print(f"{GREEN}✓ Remote certificate pin loaded{RESET}")
            else:
                print(f"{RED}✗ Root CA certificate not found at {ca_cert_file}{RESET}")
                if self._is_local_host():
                    print(f"{YELLOW}! Run generate_certificates.py or start the server once to create ca.crt and server.crt{RESET}")
                else:
                    print(f"{YELLOW}! Copy the server's ca.crt to that path or pass --ca-cert{RESET}")
                return None
            
                                                
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            return context
        except Exception as e:
            print(f"{RED}✗ SSL setup error: {e}{RESET}")
            return None

    def clear_screen(self):
                             
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
                             
        self.clear_screen()
        
        print()
        print(f"{CYAN}{'=' * 70}{RESET}")
        print(f"{WHITE}{BOLD}{'pyMESSENGER V2.1':^70}{RESET}")
        print(f"{GRAY}{'End-to-End Encrypted Messaging':^70}{RESET}")
        print(f"{CYAN}{'=' * 70}{RESET}")
        print()

    def authentication_menu(self):
                                          
        self.show_banner()
        
        print(f"{WHITE}{BOLD}  Please select an option:{RESET}\n")
        print(f"    {CYAN}1.{RESET} Create new account")
        print(f"    {CYAN}2.{RESET} Login to existing account")
        print(f"    {CYAN}3.{RESET} Exit")
        print()
        
        while True:
            choice = input(f"{CYAN}  Choice [1-3]:{RESET} ").strip()
            if choice == '1':
                if self.register_user():
                    return True
            elif choice == '2':
                if self.login_user():
                    return True
            elif choice == '3':
                return False
            else:
                print(f"{RED}  ✗ Invalid choice. Please try again.{RESET}")

    def register_user(self):
                                       
        self.clear_screen()
        
        print()
        print(f"{CYAN}{'=' * 70}{RESET}")
        print(f"{WHITE}{BOLD}{'CREATE NEW ACCOUNT':^70}{RESET}")
        print(f"{CYAN}{'=' * 70}{RESET}")
        print()
        print(f"{YELLOW}  • Password must be at least 6 characters long{RESET}")
        print(f"{YELLOW}  • Type '!back' at any prompt to return to main menu{RESET}")
        print()
        
        username = input(f"  {CYAN}Username:{RESET} ").strip()
        if username.lower() == '!back':
            return False
        
        while True:
            password = getpass.getpass(f"  {CYAN}Password:{RESET} ")
            if password.lower() == '!back':
                return False
                
            if len(password) < 6:
                print(f"{RED}  ✗ Password must be at least 6 characters long.{RESET}")
                continue
                
            confirm = getpass.getpass(f"  {CYAN}Confirm:{RESET} ")
            if confirm.lower() == '!back':
                return False
                
            if password != confirm:
                print(f"{RED}  ✗ Passwords don't match. Try again.{RESET}")
                continue
            break
        
        print(f"\n  {CYAN}→ Generating encryption keys...{RESET}")
        
                                      
        rsa_key = RSA.generate(2048)
        private_key_bytes = rsa_key.export_key()
        public_key_bytes = rsa_key.publickey().export_key()
        
        print(f"  {GREEN}✓ Encryption keys generated{RESET}")
        
                                        
        return self.authenticate_with_server(
            'register', username, password, public_key_bytes, rsa_key, private_key_bytes
        )

    def login_user(self):
                                
        self.clear_screen()
        
        print()
        print(f"{CYAN}{'=' * 70}{RESET}")
        print(f"{WHITE}{BOLD}{'LOGIN TO YOUR ACCOUNT':^70}{RESET}")
        print(f"{CYAN}{'=' * 70}{RESET}")
        print()
        print(f"{YELLOW}  • Type '!back' to return to main menu{RESET}")
        print()
        
        username = input(f"  {CYAN}Username:{RESET} ").strip()
        if username.lower() == '!back':
            return False
        
                                                     
        if not self.key_manager.key_exists(username):
            print(f"\n  {RED}✗ No account found for username '{username}'{RESET}")
            print(f"\n{YELLOW}  Would you like to:{RESET}")
            print(f"    {CYAN}1.{RESET} Try a different username")
            print(f"    {CYAN}2.{RESET} Create a new account")
            print(f"    {CYAN}3.{RESET} Return to main menu")
            
            choice = input(f"\n  {CYAN}Choice [1-3]:{RESET} ").strip()
            if choice == '1':
                return self.login_user()
            elif choice == '2':
                return self.register_user()
            else:
                return False
            
        password = getpass.getpass(f"  {CYAN}Password:{RESET} ")
        if password.lower() == '!back':
            return False
        
        print(f"\n  {CYAN}→ Loading local encryption keys...{RESET}")
        
                                             
        rsa_key = self.key_manager.load_private_key(username, password)
        
        if rsa_key is None:
            print(f"  {RED}✗ Incorrect password{RESET}")
            print(f"\n{YELLOW}  Would you like to:{RESET}")
            print(f"    {CYAN}1.{RESET} Try again")
            print(f"    {CYAN}2.{RESET} Return to main menu")
            
            choice = input(f"\n  {CYAN}Choice [1-2]:{RESET} ").strip()
            if choice == '1':
                return self.login_user()
            else:
                return False
        
        print(f"  {GREEN}✓ Local keys loaded{RESET}")
        public_key_bytes = rsa_key.publickey().export_key()
        
                                  
        return self.authenticate_with_server(
            'login', username, password, public_key_bytes, rsa_key
        )

    def authenticate_with_server(self, auth_type, username, password, public_key_bytes, rsa_key, private_key_bytes=None):
                                       
        try:
            print()
            print(f"  {CYAN}→ Connecting to server...{RESET}")
            
                               
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
                                               
            if self.ssl_context:
                try:
                    temp_socket = self.ssl_context.wrap_socket(
                        temp_socket,
                        server_hostname=self.host
                    )
                    temp_socket.connect((self.host, self.port))

                    if not self._is_local_host() and self._remote_peer_fingerprint:
                        peer_cert = temp_socket.getpeercert(binary_form=True)
                        actual_fingerprint = hashlib.sha256(peer_cert).hexdigest()
                        if actual_fingerprint != self._remote_peer_fingerprint:
                            print(f"  {RED}✗ Server certificate pin mismatch{RESET}")
                            print(f"  {YELLOW}! Expected: {self._remote_peer_fingerprint}{RESET}")
                            print(f"  {YELLOW}! Actual:   {actual_fingerprint}{RESET}")
                            temp_socket.close()
                            input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                            return False

                    print(f"  {GREEN}✓ Secure connection established (TLS/SSL){RESET}")
                    
                                                      
                    cipher = temp_socket.cipher()
                    if cipher:
                        print(f"  {BLUE}  Cipher: {cipher[0]}{RESET}")
                except ssl.SSLError as e:
                    print(f"  {RED}✗ SSL connection failed: {e}{RESET}")
                    temp_socket.close()
                    input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                    return False
            else:
                print(f"  {RED}✗ No SSL certificate available{RESET}")
                print(f"  {YELLOW}! Cannot connect without secure encryption{RESET}")
                input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                return False
            
                                                 
            print(f"  {CYAN}→ Initiating authentication...{RESET}")
            
            if auth_type == 'register':
                                                                      
                auth_request = {
                    'type': 'auth_request',
                    'auth_type': 'register',
                    'username': username,
                    'password': password,
                    'pubkey': base64.b64encode(public_key_bytes).decode('utf-8')
                }
                send_json(temp_socket, auth_request)
                
                                  
                response = recv_json(temp_socket)
                
                if not response or response.get('type') != 'auth_response':
                    print(f"  {RED}✗ Invalid server response{RESET}")
                    temp_socket.close()
                    input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                    return False
                
                if not response.get('success'):
                    print(f"  {RED}✗ {response.get('message', 'Registration failed')}{RESET}")
                    temp_socket.close()
                    input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                    return False

                if private_key_bytes is not None:
                    try:
                        self.key_manager.save_private_key(username, private_key_bytes, password)
                        print(f"  {GREEN}✓ Encryption keys stored locally{RESET}")
                    except Exception as e:
                        print(f"  {RED}✗ Failed to store local encryption keys: {e}{RESET}")
                        temp_socket.close()
                        input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                        return False
                
                print(f"  {GREEN}✓ {response.get('message')}{RESET}")
                
            else:                                 
                                                           
                auth_request = {
                    'type': 'auth_request',
                    'auth_type': 'login',
                    'username': username,
                    'pubkey': base64.b64encode(public_key_bytes).decode('utf-8')
                }
                send_json(temp_socket, auth_request)
                
                                                       
                challenge_msg = recv_json(temp_socket)
                
                if not challenge_msg or challenge_msg.get('type') != 'auth_challenge':
                    error = challenge_msg.get('message', 'Invalid challenge') if challenge_msg else 'No response'
                    print(f"  {RED}✗ {error}{RESET}")
                    temp_socket.close()
                    input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                    return False
                
                nonce = challenge_msg.get('nonce')
                salt_b64 = challenge_msg.get('salt')
                
                if not nonce or not salt_b64:
                    print(f"  {RED}✗ Invalid challenge format{RESET}")
                    temp_socket.close()
                    input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                    return False

                print(f"  {CYAN}→ Solving authentication challenge...{RESET}")
                
                                                                   
                                                         
                import hmac
                
                salt = base64.b64decode(salt_b64)
                
                                                                 
                password_key = PBKDF2(
                    password.encode('utf-8'),
                    salt,                  
                    32,
                    count=100000,
                    hmac_hash_module=SHA256
                )
                
                                       
                nonce_bytes = nonce.encode('utf-8')
                response_hash = hmac.new(password_key, nonce_bytes, hashlib.sha256).digest()
                response_b64 = base64.b64encode(response_hash).decode('utf-8')
                
                                                 
                response_msg = {
                    'type': 'auth_response',
                    'response': response_b64
                }
                send_json(temp_socket, response_msg)
                
                                                       
                result = recv_json(temp_socket)
                
                if not result or result.get('type') != 'auth_result':
                    print(f"  {RED}✗ Invalid server response{RESET}")
                    temp_socket.close()
                    input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                    return False
                
                if not result.get('success'):
                    print(f"  {RED}✗ {result.get('message', 'Authentication failed')}{RESET}")
                    temp_socket.close()
                    input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                    return False
                
                print(f"  {GREEN}✓ {result.get('message')}{RESET}")
                response = result                                    

                                                                                                   
            material = self._ensure_signal_material(username, password)
            if not self._upload_signal_bundle(temp_socket, material):
                temp_socket.close()
                input(f"\n  {GRAY}Press Enter to continue...{RESET}")
                return False
            
            self.username = username
            self.rsa_key = rsa_key
            self.session_token = response.get('session_token')
            self.signal_material = material
            self.client_socket = temp_socket
            
            return True
            
        except ConnectionRefusedError:
            print(f"  {RED}✗ Could not connect to server{RESET}")
            input(f"\n  {GRAY}Press Enter to continue...{RESET}")
            return False
        except Exception as e:
            print(f"  {RED}✗ Authentication error: {e}{RESET}")
            import traceback
            traceback.print_exc()
            input(f"\n  {GRAY}Press Enter to continue...{RESET}")
            return False

    def _ensure_signal_material(self, username, password):
                                                                               
        material = self.signal_store.load(username, password)
        if material is None:
            print(f"  {CYAN}→ Generating Signal identity keys...{RESET}")
            material = SignalKeyMaterial.generate(username)
        else:
            material.username = username
            material.rotate_prekey_bundle(50)
            print(f"  {GREEN}✓ Signal identity keys loaded and rotated{RESET}")

        self.signal_store.save(username, material, password)
        return material

    def _upload_signal_bundle(self, sock, material):
                                                                                               
        try:
            send_json(sock, {
                'type': 'signal_bundle_upload',
                'bundle': material.to_public_bundle()
            })

            response = recv_json(sock)
            if not response or response.get('type') != 'signal_bundle_ack':
                print(f"  {RED}✗ Invalid Signal bundle response from server{RESET}")
                return False

            if not response.get('success'):
                print(f"  {RED}✗ {response.get('message', 'Signal bundle upload failed')}{RESET}")
                return False

            print(f"  {GREEN}✓ Signal bundle synchronized with server{RESET}")
            return True
        except Exception as e:
            print(f"  {RED}✗ Signal bundle upload failed: {e}{RESET}")
            return False

    def _register_pending_request(self, request_id):
        event = threading.Event()
        with self.pending_requests_lock:
            self.pending_requests[request_id] = {
                'event': event,
                'response': None
            }
        return event

    def _complete_pending_request(self, request_id, response):
        with self.pending_requests_lock:
            pending = self.pending_requests.get(request_id)
            if not pending:
                return
            pending['response'] = response
            pending['event'].set()

    def _request_signal_bundle(self, target, timeout=10):
                                                                                     
        request_id = secrets.token_urlsafe(16)
        event = self._register_pending_request(request_id)

        try:
            send_json(self.client_socket, {
                'type': 'signal_bundle_request',
                'target': target,
                'request_id': request_id,
                'from': self.username
            })

            if not event.wait(timeout):
                with self.pending_requests_lock:
                    self.pending_requests.pop(request_id, None)
                return None

            with self.pending_requests_lock:
                pending = self.pending_requests.pop(request_id, None)

            response = pending['response'] if pending else None
            if not response or not response.get('success'):
                return None

            bundle = SignalPeerBundle.from_dict(target, response['bundle'])
            bundle.verify()
            return bundle
        except Exception as e:
            with self.pending_requests_lock:
                self.pending_requests.pop(request_id, None)
            print(f"{RED}✗ Failed to load Signal bundle for {target}: {e}{RESET}")
            return None

    def _encrypt_signal_message(self, target, plaintext, is_private):
                                                                            
        session = self.signal_sessions.get(target)

        if session is None:
            peer_bundle = self._request_signal_bundle(target)
            if peer_bundle is None:
                self.display_message(f"{RED}⚠ Unable to fetch Signal bundle for {target}.{RESET}", 'error')
                return False

            try:
                session, packet = create_initiator_session(
                    self.signal_material,
                    peer_bundle,
                    plaintext,
                    self.username,
                    target,
                    is_private,
                )
            except Exception as e:
                self.display_message(f"{RED}⚠ Signal session setup failed for {target}: {e}{RESET}", 'error')
                return False

            self.signal_sessions[target] = session
        else:
            try:
                packet = encrypt_session_message(
                    session,
                    plaintext,
                    self.username,
                    target,
                    is_private,
                )
            except Exception as e:
                self.display_message(f"{RED}⚠ Signal encryption failed for {target}: {e}{RESET}", 'error')
                return False

        send_json(self.client_socket, {
            'type': 'signal_send',
            'from': self.username,
            'target': target,
            'packet': packet,
        })
        return True

    def start(self):
                               
        if not self.authentication_menu():
            print(f"\n{BLUE}{BOX_TL}{BOX_H * 13}{BOX_TR}")
            print(f"{BLUE}{BOX_V}{RESET} Goodbye! 👋 {BLUE}{BOX_V}{RESET}")
            print(f"{BLUE}{BOX_BL}{BOX_H * 13}{BOX_BR}{RESET}")
            return
        
        try:
            self.running = True
            
                                   
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
                                    
            self.show_chat_interface()
            
                                                     
            self.prompt_session = PromptSession(erase_when_done=True)
            
                                                          
            with patch_stdout():
                while self.running:
                    try:
                                                              
                        if self.current_room:
                            prompt_html = f'<ansibrightmagenta>to @{self.current_room} ></ansibrightmagenta> '
                        else:
                            prompt_html = '<ansibrightcyan>></ansibrightcyan> '
                        
                                                                      
                        message = self.prompt_session.prompt(
                            HTML(prompt_html),
                            multiline=False
                        )
                        
                        if not message:
                            continue
                        
                        if message.lower() in ['quit', 'exit', 'break', 'disconnect']:
                            break
                        
                        if message.startswith('/'):
                            self.handle_command(message)
                            continue

                                                         
                        if self.current_room:
                                                                        
                            if self.current_room not in self.peer_keys:
                                self.display_message(f"{YELLOW}⚠ User '{self.current_room}' is offline. Leaving room.{RESET}", 'system')
                                self.current_room = None
                                self.show_chat_interface()
                                continue
                            targets = [self.current_room]
                            msg_color = MAGENTA
                            msg_prefix = f"[To {self.current_room}]"
                        else:
                                                                
                            targets = [n for n in self.peer_keys.keys() if n != self.username]
                            if not targets:
                                self.display_message(f"{YELLOW}⚠ No recipients available.{RESET}", 'system')
                                continue
                            msg_color = BLUE
                            msg_prefix = "[You]"

                        try:
                                                                                    
                            message_bytes = message.encode('utf-8', errors='surrogatepass')
                        except Exception as e:
                            self.display_message(f"{RED}⚠ Could not encode message: {e}{RESET}", 'error')
                            continue

                                                                      
                        timestamp = datetime.now().strftime("%H:%M")
                        msg_display = f"{GRAY}[{timestamp}] {msg_color}{msg_prefix}{RESET} {message}"
                        self.display_message(msg_display, 'outgoing')
                        
                        self.encrypt_and_send_message(message_bytes, targets)
                        
                    except KeyboardInterrupt:
                        break
                    except EOFError:
                        break
                    except Exception as e:
                        self.display_message(f"{RED}Error: {e}{RESET}", 'error')
                        break
                    
        except Exception as e:
            print(f"{RED}⚠ Client error: {e}{RESET}")
        finally:
            self.stop()

    def show_chat_interface(self):
        self.clear_screen()
        
                                    
        if self.current_room:
                                                   
            theme_color = MAGENTA
            border_color = RED
            mode_text = f"PRIVATE CHAT with {self.current_room}"
            mode_indicator = f"{RED}[PRIVATE ROOM: {self.current_room}]{RESET}"
        else:
                                              
            theme_color = CYAN
            border_color = CYAN
            mode_text = "pyMESSENGER"
            mode_indicator = f"{CYAN}[BROADCAST MODE]{RESET}"
        
        print_formatted_text(ANSI(""))
        print_formatted_text(ANSI(f"{border_color}{'=' * 70}{RESET}"))
        print_formatted_text(ANSI(f"{WHITE}{BOLD}{mode_text:^70}{RESET}"))
        print_formatted_text(ANSI(f"{border_color}{'=' * 70}{RESET}"))
        print_formatted_text(ANSI(f"{GRAY}  Logged in as: {BOLD}{self.username}{RESET}"))
        print_formatted_text(ANSI(f"{GRAY}  Mode: {mode_indicator}"))
        print_formatted_text(ANSI(f"{GRAY}{'=' * 70}{RESET}"))
        print_formatted_text(ANSI(""))
        
        print_formatted_text(ANSI(f"{WHITE}{BOLD}Commands:{RESET}"))
        print_formatted_text(ANSI(f"  {theme_color}/room <user>{RESET}        Enter private room with user"))
        print_formatted_text(ANSI(f"  {theme_color}/leave{RESET}              Leave private room (return to broadcast)"))
        print_formatted_text(ANSI(f"  {theme_color}/msg <user> <text>{RESET}  Send single private message"))
        print_formatted_text(ANSI(f"  {theme_color}/sendfile <user> <path>{RESET}  Send file to user"))
        print_formatted_text(ANSI(f"  {theme_color}/acceptfile [#]{RESET}     Accept pending file transfer"))
        print_formatted_text(ANSI(f"  {theme_color}/rejectfile [#]{RESET}     Reject pending file transfer"))
        print_formatted_text(ANSI(f"  {theme_color}/history [count]{RESET}    View message history"))
        print_formatted_text(ANSI(f"  {theme_color}/users{RESET}              List online users"))
        print_formatted_text(ANSI(f"  {theme_color}/clear{RESET}              Clear screen"))
        print_formatted_text(ANSI(f"  {theme_color}/help{RESET}               Show help"))
        print_formatted_text(ANSI(f"  {theme_color}/exit{RESET}               Exit chat"))
        print_formatted_text(ANSI(""))
        print_formatted_text(ANSI(f"{GRAY}{'─' * 70}{RESET}"))
        print_formatted_text(ANSI(""))

    def handle_command(self, message):
                              
        parts = message.split(' ', 2)
        command = parts[0].lower()
        
        if command == '/room' and len(parts) >= 2:
            target = parts[1]
            
            if target == self.username:
                print_formatted_text(ANSI(f"{YELLOW}⚠ You cannot create a room with yourself.{RESET}"))
                return
            
            if target not in self.peer_keys:
                print_formatted_text(ANSI(f"{YELLOW}⚠ User '{target}' is not online.{RESET}"))
                return
            
                                            
            send_json(self.client_socket, {
                'type': 'room_invite',
                'target': target
            })
            
            print_formatted_text(ANSI(f"{CYAN}→ Sending room invitation to {target}...{RESET}"))
            print_formatted_text(ANSI(f"{GRAY}  Waiting for {target} to accept...{RESET}\n"))
            
        elif command == '/leave':
            if not self.current_room:
                print_formatted_text(ANSI(f"{YELLOW}⚠ You are not in a private room.{RESET}"))
                return
            
            previous_room = self.current_room
            self.current_room = None
            self.show_chat_interface()
            print_formatted_text(ANSI(f"{CYAN}✓ Left private room with {previous_room}{RESET}"))
            print_formatted_text(ANSI(f"{GRAY}  Returned to broadcast mode.{RESET}\n"))
        
        elif command == '/accept':
                                            
            with self.invite_lock:
                if not self.pending_invite:
                    print_formatted_text(ANSI(f"{YELLOW}⚠ No pending room invitation.{RESET}"))
                    return
                
                invite_id = self.pending_invite['invite_id']
                sender = self.pending_invite['from']
            
                                       
            send_json(self.client_socket, {
                'type': 'room_invite_response',
                'invite_id': invite_id,
                'accepted': True
            })
            
            print_formatted_text(ANSI(f"{GREEN}✓ Accepting room invitation from {sender}...{RESET}\n"))
        
        elif command == '/decline':
                                             
            with self.invite_lock:
                if not self.pending_invite:
                    print_formatted_text(ANSI(f"{YELLOW}⚠ No pending room invitation.{RESET}"))
                    return
                
                invite_id = self.pending_invite['invite_id']
                sender = self.pending_invite['from']
            
                                      
            send_json(self.client_socket, {
                'type': 'room_invite_response',
                'invite_id': invite_id,
                'accepted': False
            })
            
            print_formatted_text(ANSI(f"{YELLOW}✗ Declined room invitation from {sender}.{RESET}\n"))
            
                                  
            with self.invite_lock:
                self.pending_invite = None
        
        elif command == '/msg' and len(parts) >= 3:
            target = parts[1]
            content = parts[2]
            
            if target not in self.peer_keys:
                print_formatted_text(ANSI(f"{YELLOW}⚠ User '{target}' not online.{RESET}"))
                return
                
            self.encrypt_and_send_message(content.encode('utf-8'), [target])
            timestamp = datetime.now().strftime("%H:%M")
            msg_display = f"{GRAY}[{timestamp}] {MAGENTA}[To {target}]-(priv){RESET} {content}"
            self.display_message(msg_display, 'outgoing')
            
        elif command == '/history':
                                     
            count = 20                               
            if len(parts) > 1:
                try:
                    count = int(parts[1])
                    count = min(count, 100)                    
                except ValueError:
                    print_formatted_text(ANSI(f"{RED}Invalid number. Usage: /history [count]{RESET}"))
                    return
            
            with self.history_lock:
                history = list(self.message_history)
            
            if not history:
                print_formatted_text(ANSI(f"{YELLOW}No message history available.{RESET}"))
                return
            
            print_formatted_text(ANSI(f"\n{WHITE}{BOLD}Message History (last {len(history[-count:])} messages):{RESET}"))
            print_formatted_text(ANSI(f"{GRAY}{'─' * 60}{RESET}"))
            for msg in history[-count:]:
                print_formatted_text(ANSI(msg['message']))
            print_formatted_text(ANSI(f"{GRAY}{'─' * 60}{RESET}\n"))
            
        elif command == '/help':
                                   
            theme_color = MAGENTA if self.current_room else CYAN
            
            print_formatted_text(ANSI(f"\n{WHITE}{BOLD}Available Commands:{RESET}"))
            print_formatted_text(ANSI(f"{GRAY}{'─' * 60}{RESET}"))
            print_formatted_text(ANSI(f"  {theme_color}/room <user>{RESET}"))
            print_formatted_text(ANSI(f"    Enter private room with <user>. All messages will be"))
            print_formatted_text(ANSI(f"    sent only to that user until you /leave."))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/leave{RESET}"))
            print_formatted_text(ANSI(f"    Leave current private room and return to broadcast mode."))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/msg <user> <message>{RESET}"))
            print_formatted_text(ANSI(f"    Send a single private message without entering a room."))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/sendfile <user> <filepath>{RESET}"))
            print_formatted_text(ANSI(f"    Send a file to <user>. Files are encrypted end-to-end."))
            print_formatted_text(ANSI(f"    Example: /sendfile alice ~/Documents/report.pdf"))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/acceptfile [number]{RESET}"))
            print_formatted_text(ANSI(f"    Accept a pending file transfer. Use without number to"))
            print_formatted_text(ANSI(f"    see all pending offers. Files saved to:"))
            print_formatted_text(ANSI(f"    ~/.secure_messenger_client/files/received/"))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/rejectfile [number]{RESET}"))
            print_formatted_text(ANSI(f"    Reject a pending file transfer offer."))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/users{RESET}"))
            print_formatted_text(ANSI(f"    List all online users."))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/history [count]{RESET}"))
            print_formatted_text(ANSI(f"    View message history (default: 20, max: 100)."))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/clear{RESET}"))
            print_formatted_text(ANSI(f"    Clear screen and refresh interface."))
            print_formatted_text(ANSI(f""))
            print_formatted_text(ANSI(f"  {theme_color}/exit{RESET}"))
            print_formatted_text(ANSI(f"    Exit the application."))
            print_formatted_text(ANSI(f"{GRAY}{'─' * 60}{RESET}\n"))
            
        elif command == '/users':
            theme_color = MAGENTA if self.current_room else CYAN
            
            if not self.peer_keys:
                print_formatted_text(ANSI(f"{YELLOW}No other users online.{RESET}"))
            else:
                print_formatted_text(ANSI(f"\n{WHITE}{BOLD}Online users:{RESET}"))
                for i, user in enumerate(self.peer_keys.keys(), 1):
                    if user != self.username:
                                                     
                        if user == self.current_room:
                            print_formatted_text(ANSI(f"  {theme_color}{i}.{RESET} {user} {MAGENTA}(in room){RESET}"))
                        else:
                            print_formatted_text(ANSI(f"  {theme_color}{i}.{RESET} {user}"))
                print_formatted_text(ANSI(""))
        
        elif command == '/sendfile' and len(parts) >= 3:
            target = parts[1]
            filepath = parts[2]
            
                                       
            if target not in self.peer_keys:
                print_formatted_text(ANSI(f"{YELLOW}⚠ User '{target}' is not online.{RESET}"))
                return
            
                                  
            file_path = Path(filepath).expanduser()
            if not file_path.exists():
                print_formatted_text(ANSI(f"{RED}✗ File not found: {filepath}{RESET}"))
                return
            
            if not file_path.is_file():
                print_formatted_text(ANSI(f"{RED}✗ Not a file: {filepath}{RESET}"))
                return
            
                                                    
            threading.Thread(
                target=self.send_file,
                args=(target, file_path),
                daemon=True
            ).start()
        
        elif command == '/acceptfile':
                                       
            with self.file_lock:
                if not self.pending_file_offers:
                    print_formatted_text(ANSI(f"{YELLOW}⚠ No pending file offers.{RESET}"))
                    return
                
                                     
                if len(parts) < 2:
                    print_formatted_text(ANSI(f"\n{WHITE}{BOLD}Pending file offers:{RESET}"))
                    for i, (file_id, offer) in enumerate(self.pending_file_offers.items(), 1):
                        size_mb = offer['filesize'] / (1024 * 1024)
                        print_formatted_text(ANSI(f"  {CYAN}{i}.{RESET} {offer['filename']} ({size_mb:.2f} MB) from {offer['from']}"))
                        print_formatted_text(ANSI(f"     File ID: {file_id}"))
                    print_formatted_text(ANSI(f"\n{GRAY}Usage: /acceptfile <number>{RESET}\n"))
                    return
                
                try:
                    choice = int(parts[1]) - 1
                    file_id = list(self.pending_file_offers.keys())[choice]
                    offer = self.pending_file_offers[file_id]
                except (ValueError, IndexError):
                    print_formatted_text(ANSI(f"{RED}✗ Invalid selection{RESET}"))
                    return
            
                             
            send_json(self.client_socket, {
                'type': 'file_response',
                'file_id': file_id,
                'accepted': True,
                'sender': offer['from']
            })
            
            print_formatted_text(ANSI(f"{GREEN}✓ Accepting file: {offer['filename']}{RESET}"))
            print_formatted_text(ANSI(f"{GRAY}  Waiting for transfer to begin...{RESET}\n"))
        
        elif command == '/rejectfile':
                                       
            with self.file_lock:
                if not self.pending_file_offers:
                    print_formatted_text(ANSI(f"{YELLOW}⚠ No pending file offers.{RESET}"))
                    return
                
                                     
                if len(parts) < 2:
                    print_formatted_text(ANSI(f"\n{WHITE}{BOLD}Pending file offers:{RESET}"))
                    for i, (file_id, offer) in enumerate(self.pending_file_offers.items(), 1):
                        size_mb = offer['filesize'] / (1024 * 1024)
                        print_formatted_text(ANSI(f"  {CYAN}{i}.{RESET} {offer['filename']} ({size_mb:.2f} MB) from {offer['from']}"))
                    print_formatted_text(ANSI(f"\n{GRAY}Usage: /rejectfile <number>{RESET}\n"))
                    return
                
                try:
                    choice = int(parts[1]) - 1
                    file_id = list(self.pending_file_offers.keys())[choice]
                    offer = self.pending_file_offers.pop(file_id)
                except (ValueError, IndexError):
                    print_formatted_text(ANSI(f"{RED}✗ Invalid selection{RESET}"))
                    return
            
                            
            send_json(self.client_socket, {
                'type': 'file_response',
                'file_id': file_id,
                'accepted': False,
                'sender': offer['from']
            })
            
            print_formatted_text(ANSI(f"{YELLOW}✗ Rejected file: {offer['filename']}{RESET}\n"))
                
        elif command == '/clear':
            self.show_chat_interface()
            
        elif command == '/exit':
            self.running = False
            
        else:
            print_formatted_text(ANSI(f"{YELLOW}Unknown command. Type /help for available commands.{RESET}"))

    def encrypt_and_send_message(self, plaintext, targets):
                                       
        if not self.signal_material:
            self.display_message(f"{RED}⚠ Signal identity keys are not ready yet.{RESET}", 'error')
            return

        is_private = len(targets) == 1
        for target in targets:
            if target == self.username:
                continue
            self._encrypt_signal_message(target, plaintext, is_private)

    def _display_decrypted_message(self, sender, message_text, is_private):
                                                                        
        mentions = self.detect_mentions(message_text)
        is_mentioned = self.username in mentions
        highlighted_text = self.highlight_mentions(message_text, self.username)

        timestamp = datetime.now().strftime("%H:%M")

        if is_mentioned:
            if is_private:
                msg = f"{GRAY}[{timestamp}] {YELLOW}{BOLD}[{sender}]-(priv)(@mentioned you){RESET} {highlighted_text}"
            else:
                msg = f"{GRAY}[{timestamp}] {YELLOW}{BOLD}[{sender}](@mentioned you){RESET} {highlighted_text}"
        else:
            if is_private:
                msg = f"{GRAY}[{timestamp}] {GREEN}[{sender}]-(priv){RESET} {highlighted_text}"
            else:
                msg = f"{GRAY}[{timestamp}] {GREEN}[{sender}]{RESET} {highlighted_text}"

        self.display_message(msg, 'incoming')
    
    def send_file(self, target, file_path):
                                         
        try:
            import secrets
            
                                     
            file_id = secrets.token_urlsafe(16)
            filename = file_path.name
            filesize = file_path.stat().st_size
            
            print_formatted_text(ANSI(f"\n{CYAN}→ Preparing to send file:{RESET}"))
            print_formatted_text(ANSI(f"  {WHITE}File:{RESET} {filename}"))
            print_formatted_text(ANSI(f"  {WHITE}Size:{RESET} {filesize / (1024*1024):.2f} MB"))
            print_formatted_text(ANSI(f"  {WHITE}To:{RESET} {target}\n"))
            
                                     
            with self.file_lock:
                self.pending_file_sends[file_id] = {
                    'target': target,
                    'file_path': file_path
                }
            
                             
            send_json(self.client_socket, {
                'type': 'file_offer',
                'target': target,
                'filename': filename,
                'filesize': filesize,
                'file_id': file_id
            })
            
            print_formatted_text(ANSI(f"{GRAY}Waiting for {target} to accept...{RESET}\n"))
            
        except Exception as e:
            print_formatted_text(ANSI(f"{RED}✗ File send error: {e}{RESET}\n"))
    
    def send_file_chunks(self, target, file_path, file_id):
                                            
        try:
            CHUNK_SIZE = 64 * 1024                
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            total_chunks = (len(file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            print_formatted_text(ANSI(f"{CYAN}→ Sending file in {total_chunks} chunks...{RESET}"))
            
            for chunk_num in range(1, total_chunks + 1):
                start = (chunk_num - 1) * CHUNK_SIZE
                end = min(start + CHUNK_SIZE, len(file_data))
                chunk = file_data[start:end]
                
                                        
                aes_key = get_random_bytes(32)
                aes_cipher = AES.new(aes_key, AES.MODE_EAX)
                encrypted_chunk, tag = aes_cipher.encrypt_and_digest(chunk)
                
                                                             
                pub = self.peer_keys.get(target)
                if not pub:
                    print_formatted_text(ANSI(f"{RED}✗ Recipient went offline{RESET}\n"))
                    return False
                
                rsa_cipher = PKCS1_OAEP.new(pub)
                encrypted_key = rsa_cipher.encrypt(aes_key)
                
                                      
                send_json(self.client_socket, {
                    'type': 'file_transfer',
                    'target': target,
                    'file_id': file_id,
                    'chunk_num': chunk_num,
                    'total_chunks': total_chunks,
                    'encrypted_chunk': base64.b64encode(encrypted_chunk).decode('utf-8'),
                    'nonce': base64.b64encode(aes_cipher.nonce).decode('utf-8'),
                    'tag': base64.b64encode(tag).decode('utf-8'),
                    'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8')
                })
                
                               
                if chunk_num % 10 == 0 or chunk_num == total_chunks:
                    progress = (chunk_num / total_chunks) * 100
                    print_formatted_text(ANSI(f"{GRAY}  Progress: {progress:.1f}% ({chunk_num}/{total_chunks}){RESET}"))
            
            print_formatted_text(ANSI(f"{GREEN}✓ File sent successfully!{RESET}\n"))
            
                                            
            sent_path = self.key_manager.sent_dir / safe_path_component(file_path.name, 'sent_file')
            import shutil
            shutil.copy2(file_path, sent_path)
            
            return True
            
        except Exception as e:
            print_formatted_text(ANSI(f"{RED}✗ Error sending file: {e}{RESET}\n"))
            return False
    
    def send_file_chunks_by_id(self, file_id):
                                                    
        try:
            with self.file_lock:
                if file_id not in self.pending_file_sends:
                    print_formatted_text(ANSI(f"{RED}✗ File transfer info not found{RESET}\n"))
                    return
                
                send_info = self.pending_file_sends.pop(file_id)
            
            target = send_info['target']
            file_path = send_info['file_path']
            
            return self.send_file_chunks(target, file_path, file_id)
            
        except Exception as e:
            print_formatted_text(ANSI(f"{RED}✗ Error initiating file send: {e}{RESET}\n"))
            return False
    
    def receive_file_chunk(self, pkg):
                                             
        try:
            file_id = pkg.get('file_id')
            sender = pkg.get('from')
            chunk_num = pkg.get('chunk_num')
            total_chunks = pkg.get('total_chunks')
            encrypted_chunk = base64.b64decode(pkg.get('encrypted_chunk'))
            nonce = base64.b64decode(pkg.get('nonce'))
            tag = base64.b64decode(pkg.get('tag'))
            encrypted_key = base64.b64decode(pkg.get('encrypted_key'))
            
                             
            rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
            aes_key = rsa_cipher.decrypt(encrypted_key)
            
                           
            aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            chunk = aes_cipher.decrypt_and_verify(encrypted_chunk, tag)
            
                         
            with self.file_lock:
                if file_id not in self.active_file_transfers:
                                                  
                    offer = self.pending_file_offers.get(file_id, {})
                    self.active_file_transfers[file_id] = {
                        'chunks': {},
                        'total': total_chunks,
                        'filename': offer.get('filename', 'unknown'),
                        'from': sender
                    }
                                         
                    self.pending_file_offers.pop(file_id, None)
                
                self.active_file_transfers[file_id]['chunks'][chunk_num] = chunk
                
                received = len(self.active_file_transfers[file_id]['chunks'])
                
                               
                if chunk_num % 10 == 0 or chunk_num == total_chunks:
                    progress = (received / total_chunks) * 100
                    print_formatted_text(ANSI(f"{GRAY}  Receiving: {progress:.1f}% ({received}/{total_chunks}){RESET}"))
                
                                   
                if received == total_chunks:
                    self.finalize_file_transfer(file_id)
        
        except Exception as e:
            print_formatted_text(ANSI(f"{RED}✗ Error receiving file chunk: {e}{RESET}\n"))
    
    def finalize_file_transfer(self, file_id):
        try:
            transfer = self.active_file_transfers[file_id]
            filename = transfer['filename']
            sender = transfer['from']                       
            complete_data = b''
            for i in range(1, transfer['total'] + 1):
                complete_data += transfer['chunks'][i]                                           
            safe_sender = safe_path_component(sender, 'peer')
            safe_name = safe_path_component(filename, 'file')
            safe_filename = f"{safe_sender}_{safe_name}"
            save_path = self.key_manager.received_dir / safe_filename
            
            counter = 1
            while save_path.exists():
                name_parts = safe_name.rsplit('.', 1)
                if len(name_parts) == 2:
                    safe_filename = f"{safe_sender}_{name_parts[0]}_{counter}.{name_parts[1]}"
                else:
                    safe_filename = f"{safe_sender}_{safe_name}_{counter}"
                save_path = self.key_manager.received_dir / safe_filename
                counter += 1
            
            with open(save_path, 'wb') as f:
                f.write(complete_data)
            
            print_formatted_text(ANSI(f"\n{GREEN}✓ File received successfully!{RESET}"))
            print_formatted_text(ANSI(f"  {WHITE}From:{RESET} {sender}"))
            print_formatted_text(ANSI(f"  {WHITE}Saved as:{RESET} {safe_filename}"))
            print_formatted_text(ANSI(f"  {WHITE}Location:{RESET} {save_path}"))
            print_formatted_text(ANSI(f"  {WHITE}Size:{RESET} {len(complete_data) / (1024*1024):.2f} MB\n"))
            
                     
            del self.active_file_transfers[file_id]
            
        except Exception as e:
            print_formatted_text(ANSI(f"{RED}✗ Error finalizing file transfer: {e}{RESET}\n"))

    def receive_messages(self):
                                       
        while self.running:
            try:
                pkg = recv_json(self.client_socket)
                if pkg is None:
                    msg = f"{RED}⚠ Server disconnected{RESET}"
                    self.display_message(msg, 'system')
                    self.running = False
                    break

                ptype = pkg.get('type')
                if ptype == 'pubkey_announce':
                    name = pkg.get('name')
                    pub_b64 = pkg.get('pubkey')
                    try:
                        pub_bytes = base64.b64decode(pub_b64)
                        pub = RSA.import_key(pub_bytes)
                        self.peer_keys[name] = pub
                        
                        msg = f"{CYAN}[i] {name}{RESET} joined"
                        self.display_message(msg, 'system')
                    except Exception:
                        pass

                elif ptype == 'signal_bundle_response':
                    request_id = pkg.get('request_id')
                    if request_id:
                        self._complete_pending_request(request_id, pkg)

                elif ptype == 'encrypted_deliver':
                    sender = pkg.get('from')
                    is_private = pkg.get('is_private', False)
                    try:
                        enc_key = base64.b64decode(pkg.get('key'))
                        ciphertext = base64.b64decode(pkg.get('ciphertext'))
                        nonce = base64.b64decode(pkg.get('nonce'))
                        tag = base64.b64decode(pkg.get('tag'))

                        rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
                        aes_key = rsa_cipher.decrypt(enc_key)
                        aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                        plaintext = aes.decrypt_and_verify(ciphertext, tag)
                        
                                            
                        message_text = plaintext.decode('utf-8')
                        self._display_decrypted_message(sender, message_text, is_private)
                        
                    except Exception:
                        msg = f"{RED}⚠ Decrypt failed from {sender}{RESET}"
                        self.display_message(msg, 'error')

                elif ptype == 'signal_session_init':
                    sender = pkg.get('from')
                    try:
                        if not self.signal_material:
                            raise ValueError('Signal identity keys not loaded')

                        session, plaintext = accept_session_init(self.signal_material, pkg)
                        self.signal_sessions[sender] = session
                        self._display_decrypted_message(
                            sender,
                            plaintext.decode('utf-8'),
                            pkg.get('is_private', False),
                        )
                    except Exception as e:
                        self.display_message(f"{RED}⚠ Signal session init failed from {sender}: {e}{RESET}", 'error')

                elif ptype == 'signal_message':
                    sender = pkg.get('from')
                    try:
                        session = self.signal_sessions.get(sender)
                        if session is None:
                            raise ValueError('No active Signal session for this peer')

                        plaintext = session.decrypt_message(pkg, sender, self.username)
                        self._display_decrypted_message(
                            sender,
                            plaintext.decode('utf-8'),
                            pkg.get('is_private', False),
                        )
                    except Exception as e:
                        self.display_message(f"{RED}⚠ Signal decrypt failed from {sender}: {e}{RESET}", 'error')

                elif ptype == 'error':
                    msg = f"{RED}⚠ Server: {pkg.get('msg')}{RESET}"
                    self.display_message(msg, 'error')
                
                                                
                elif ptype == 'room_invite_request':
                    sender = pkg.get('from')
                    invite_id = pkg.get('invite_id')
                    
                    print(f"\n{BLUE}[DEBUG]{RESET} Received room invite from {sender}, invite_id: {invite_id}")
                    
                                          
                    with self.invite_lock:
                        self.pending_invite = {
                            'from': sender,
                            'invite_id': invite_id
                        }
                    
                                                                    
                    print_formatted_text(ANSI(""))
                    print_formatted_text(ANSI(f"{GRAY}{BOLD}{'═' * 60}{RESET}"))
                    print_formatted_text(ANSI(f"{MAGENTA}{BOLD}  -> PRIVATE ROOM INVITATION{RESET}"))
                    print_formatted_text(ANSI(f"{GRAY}{BOLD}{'═' * 60}{RESET}"))
                    print_formatted_text(ANSI(f"  {WHITE}{sender}{RESET} wants to enter a private room with you."))
                    print_formatted_text(ANSI(f""))
                    print_formatted_text(ANSI(f"  Type {GREEN}/accept{RESET} to accept and enter private room"))
                    print_formatted_text(ANSI(f"  Type {RED}/decline{RESET} to decline invitation"))
                    print_formatted_text(ANSI(f"{GRAY}{BOLD}{'═' * 60}{RESET}"))
                    print_formatted_text(ANSI(""))
                
                                                 
                elif ptype == 'room_accepted':
                    partner = pkg.get('partner')
                    
                                        
                    self.current_room = partner
                    self.show_chat_interface()
                    
                    print_formatted_text(ANSI(f"{GREEN}{BOLD}✓ Private room created with {partner}!{RESET}"))
                    print_formatted_text(ANSI(f"{GRAY}  All messages will now be sent only to {partner}.{RESET}"))
                    print_formatted_text(ANSI(f"{GRAY}  Type /leave to return to broadcast mode.{RESET}\n"))
                    
                                          
                    with self.invite_lock:
                        self.pending_invite = None
                
                                                 
                elif ptype == 'room_rejected':
                    user = pkg.get('user')
                    
                    print_formatted_text(ANSI(f"\n{RED}✗ {user} declined your room invitation.{RESET}\n"))
                
                                               
                elif ptype == 'room_invite_failed':
                    reason = pkg.get('reason', 'Unknown error')
                    
                    print_formatted_text(ANSI(f"\n{RED}✗ Room invitation failed: {reason}{RESET}\n"))
                
                                            
                elif ptype == 'file_offer':
                    sender = pkg.get('from')
                    filename = pkg.get('filename')
                    filesize = pkg.get('filesize')
                    file_id = pkg.get('file_id')
                    
                    with self.file_lock:
                        self.pending_file_offers[file_id] = {
                            'from': sender,
                            'filename': filename,
                            'filesize': filesize
                        }
                    
                    size_mb = filesize / (1024 * 1024)
                    
                    print_formatted_text(ANSI(""))
                    print_formatted_text(ANSI(f"{GRAY}{BOLD}{'═' * 60}{RESET}"))
                    print_formatted_text(ANSI(f"{CYAN}{BOLD}  📁 FILE TRANSFER REQUEST{RESET}"))
                    print_formatted_text(ANSI(f"{GRAY}{BOLD}{'═' * 60}{RESET}"))
                    print_formatted_text(ANSI(f"  {WHITE}{sender}{RESET} wants to send you a file:"))
                    print_formatted_text(ANSI(f""))
                    print_formatted_text(ANSI(f"  {WHITE}Filename:{RESET} {filename}"))
                    print_formatted_text(ANSI(f"  {WHITE}Size:{RESET} {size_mb:.2f} MB"))
                    print_formatted_text(ANSI(f""))
                    print_formatted_text(ANSI(f"  Type {GREEN}/acceptfile 1{RESET} to accept"))
                    print_formatted_text(ANSI(f"  Type {RED}/rejectfile 1{RESET} to reject"))
                    print_formatted_text(ANSI(f"{GRAY}{BOLD}{'═' * 60}{RESET}"))
                    print_formatted_text(ANSI(""))
                
                                          
                elif ptype == 'file_offer_failed':
                    file_id = pkg.get('file_id')
                    reason = pkg.get('reason', 'Unknown error')
                    
                    print_formatted_text(ANSI(f"{RED}✗ File offer failed: {reason}{RESET}\n"))
                
                                                                     
                elif ptype == 'file_response':
                    file_id = pkg.get('file_id')
                    accepted = pkg.get('accepted')
                    recipient = pkg.get('recipient')
                    
                    if accepted:
                        print_formatted_text(ANSI(f"{GREEN}✓ {recipient} accepted your file!{RESET}"))
                        print_formatted_text(ANSI(f"{CYAN}→ Starting file transfer...{RESET}\n"))                                                           
                        threading.Thread(
                            target=self.send_file_chunks_by_id,
                            args=(file_id,),
                            daemon=True
                        ).start()
                    else:
                        print_formatted_text(ANSI(f"{YELLOW}✗ {recipient} rejected your file.{RESET}\n"))
                
                                            
                elif ptype == 'file_transfer':
                    self.receive_file_chunk(pkg)

            except Exception:
                if self.running:
                    break

    def stop(self):
                          
        self.running = False
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        print(f"{BLUE}Connection closed{RESET}")

    def add_to_history(self, message, msg_type='info'):
                                            
        with self.history_lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.message_history.append({
                'timestamp': timestamp,
                'message': message,
                'type': msg_type
            })
    
    def detect_mentions(self, text):
        import re                                                 
        mentions = re.findall(r'@([a-zA-Z0-9_-]+)', text)
        return list(set(mentions))                     
    
    def highlight_mentions(self, text, my_username):     
        import re
        def replace_mention(match):
            username = match.group(1)
            if username.lower() == my_username.lower():
                return f"{YELLOW}{BOLD}@{username}{RESET}"
            else:
                return f"{CYAN}@{username}{RESET}"
        return re.sub(r'@([a-zA-Z0-9_-]+)', replace_mention, text)
    
    def display_message(self, message, msg_type='info'):                                  
        self.add_to_history(message, msg_type)                                                       
        print_formatted_text(ANSI(message))

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Unicast Secure Messenger Client')
        parser.add_argument('--host', '-H', default='3.73.36.161',
                            help='Server address (default: 3.73.36.161)')
        parser.add_argument('--port', '-P', type=int, default=80,
                            help='Server port (default: 80)')
        parser.add_argument('--ca-cert', default=str(Path.home() / '.secure_messenger' / 'certs' / 'ca.crt'),
                            help='Path to the trusted root CA certificate (default: ~/.secure_messenger/certs/ca.crt)')
        args = parser.parse_args()

        client = Client(host=args.host, port=args.port, ca_cert_path=args.ca_cert)
        client.start()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}⚠ Interrupted by user{RESET}")
        if 'client' in locals():
            client.stop()
    except Exception as e:
        print(f"{RED}⚠ Unexpected error: {e}{RESET}")
        if 'client' in locals():
            client.stop()
    finally:
        print("Ciao ! :)\n")