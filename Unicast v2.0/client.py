import socket
import threading
import json
import base64
import struct
import getpass
import os
import sys
import argparse
import ssl
from pathlib import Path
from datetime import datetime
from collections import deque

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import HTML, ANSI
from prompt_toolkit.styles import Style

# Terminal color codes
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

# Terminal UI elements
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
    """Send JSON with length prefix."""
    data = json.dumps(obj).encode('utf-8')
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)

def recv_json(sock):
    """Receive JSON with length prefix."""
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

class KeyManager:
    """Manages local key storage for the client."""
    
    def __init__(self):
        self.config_dir = Path.home() / '.secure_messenger_client'
        self.keys_dir = self.config_dir / 'keys'
        self._initialize_directories()
    
    def _initialize_directories(self):
        """Create necessary directories."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        if os.name != 'nt':
            os.chmod(self.config_dir, 0o700)
            os.chmod(self.keys_dir, 0o700)
    
    def _derive_key(self, password, salt):
        """Derive encryption key from password."""
        return PBKDF2(
            password.encode('utf-8'),
            salt,
            32,
            count=100000,
            hmac_hash_module=SHA256
        )
    
    def save_private_key(self, username, private_key, password):
        """Save encrypted private key to disk."""
        salt = get_random_bytes(16)
        encryption_key = self._derive_key(password, salt)
        cipher = AES.new(encryption_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        
        key_file = self.keys_dir / f"{username}_private.key"
        with open(key_file, 'wb') as f:
            f.write(salt + cipher.nonce + tag + ciphertext)
        
        if os.name != 'nt':
            os.chmod(key_file, 0o600)
    
    def load_private_key(self, username, password):
        """Load and decrypt private key from disk."""
        key_file = self.keys_dir / f"{username}_private.key"
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
        """Check if a key file exists for username."""
        key_file = self.keys_dir / f"{username}_private.key"
        return key_file.exists()

class Client:
    def __init__(self, host='localhost', port=1315):
        self.host = host
        self.port = port
        self.client_socket = None
        self.running = False
        self.peer_keys = {}
        self.key_manager = KeyManager()
        
        self.username = None
        self.rsa_key = None
        self.session_token = None
        
        # Message history buffer (max 100 messages)
        self.message_history = deque(maxlen=100)
        self.history_lock = threading.Lock()
        
        # Prompt session for better input handling
        self.prompt_session = None
        
        # Room mode: None = broadcast, username = private room
        self.current_room = None
        
        # Pending room invitation
        self.pending_invite = None  # {'from': username, 'invite_id': id}
        self.invite_lock = threading.Lock()
        
        # SSL/TLS setup
        self.ssl_context = self._setup_ssl()

    def _setup_ssl(self):
        """Setup SSL/TLS context for client connections."""
        try:
            # Create SSL context for client
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            
            # Load the server certificate for verification
            cert_dir = Path.home() / '.secure_messenger' / 'certs'
            cert_file = cert_dir / 'server.crt'
            
            if cert_file.exists():
                # Use the server's certificate for verification
                context.load_verify_locations(str(cert_file))
                context.check_hostname = False  # We're using localhost/IP addresses
                context.verify_mode = ssl.CERT_REQUIRED  # REQUIRE certificate validation
                
                print(f"{GREEN}✓ SSL certificate loaded for validation{RESET}")
            else:
                # CRITICAL: Don't connect if we can't verify the server!
                print(f"{RED}✗ Server certificate not found at {cert_file}{RESET}")
                print(f"{YELLOW}! Run generate_certificates.py first or copy server.crt to {cert_dir}{RESET}")
                return None
            
            # Security settings - same as server
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            return context
        except Exception as e:
            print(f"{RED}✗ SSL setup error: {e}{RESET}")
            return None

    def clear_screen(self):
        """Clear terminal."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
        """Display banner."""
        self.clear_screen()
        
        print()
        print(f"{CYAN}{'=' * 70}{RESET}")
        print(f"{WHITE}{BOLD}{'pyMESSENGER V2.1':^70}{RESET}")
        print(f"{GRAY}{'End-to-End Encrypted Messaging':^70}{RESET}")
        print(f"{CYAN}{'=' * 70}{RESET}")
        print()

    def authentication_menu(self):
        """Display authentication menu."""
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
        """Handle user registration."""
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
        
        # Generate RSA keypair locally
        rsa_key = RSA.generate(2048)
        private_key_bytes = rsa_key.export_key()
        public_key_bytes = rsa_key.publickey().export_key()
        
        # Save private key locally
        self.key_manager.save_private_key(username, private_key_bytes, password)
        print(f"  {GREEN}✓ Encryption keys generated and stored locally{RESET}")
        
        # Connect to server and register
        return self.authenticate_with_server(
            'register', username, password, public_key_bytes, rsa_key
        )

    def login_user(self):
        """Handle user login."""
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
        
        # Check if keys exist for this username FIRST
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
        
        # Load private key from local storage
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
        
        # Authenticate with server
        return self.authenticate_with_server(
            'login', username, password, public_key_bytes, rsa_key
        )

    def authenticate_with_server(self, auth_type, username, password, public_key_bytes, rsa_key):
        """Authenticate with server."""
        try:
            print()
            print(f"  {CYAN}→ Connecting to server...{RESET}")
            
            # Connect to server
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap socket with SSL if available
            if self.ssl_context:
                try:
                    temp_socket = self.ssl_context.wrap_socket(
                        temp_socket,
                        server_hostname=self.host
                    )
                    temp_socket.connect((self.host, self.port))
                    print(f"  {GREEN}✓ Secure connection established (TLS/SSL){RESET}")
                    
                    # Display connection security info
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
            
            # Send initial authentication request
            print(f"  {CYAN}→ Initiating authentication...{RESET}")
            
            if auth_type == 'register':
                # Registration still uses password (for initial setup)
                auth_request = {
                    'type': 'auth_request',
                    'auth_type': 'register',
                    'username': username,
                    'password': password,
                    'pubkey': base64.b64encode(public_key_bytes).decode('utf-8')
                }
                send_json(temp_socket, auth_request)
                
                # Receive response
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
                
                print(f"  {GREEN}✓ {response.get('message')}{RESET}")
                
            else:  # Login with challenge-response
                # Step 1: Send login request (no password!)
                auth_request = {
                    'type': 'auth_request',
                    'auth_type': 'login',
                    'username': username,
                    'pubkey': base64.b64encode(public_key_bytes).decode('utf-8')
                }
                send_json(temp_socket, auth_request)
                
                # Step 2: Receive challenge from server
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
                
                # Step 3: Compute challenge response using password
                # Derive the same key as stored on server
                import hmac
                import hashlib
                
                salt = base64.b64decode(salt_b64)
                
                # Derive password key (same as server has stored)
                password_key = PBKDF2(
                    password.encode('utf-8'),
                    salt,  # Server's salt!
                    32,
                    count=100000,
                    hmac_hash_module=SHA256
                )
                
                # Compute HMAC response
                nonce_bytes = nonce.encode('utf-8')
                response_hash = hmac.new(password_key, nonce_bytes, hashlib.sha256).digest()
                response_b64 = base64.b64encode(response_hash).decode('utf-8')
                
                # Step 4: Send challenge response
                response_msg = {
                    'type': 'auth_response',
                    'response': response_b64
                }
                send_json(temp_socket, response_msg)
                
                # Step 5: Receive authentication result
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
                response = result  # Use this for session token below
            
            self.username = username
            self.rsa_key = rsa_key
            self.session_token = response.get('session_token')
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

    def start(self):
        """Start the client."""
        if not self.authentication_menu():
            print(f"\n{BLUE}{BOX_TL}{BOX_H * 13}{BOX_TR}")
            print(f"{BLUE}{BOX_V}{RESET} Goodbye! 👋 {BLUE}{BOX_V}{RESET}")
            print(f"{BLUE}{BOX_BL}{BOX_H * 13}{BOX_BR}{RESET}")
            return
        
        try:
            self.running = True
            
            # Start receiver thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Display chat interface
            self.show_chat_interface()
            
            # Create prompt session with custom style
            self.prompt_session = PromptSession()
            
            # Main message loop with better input handling
            with patch_stdout():
                while self.running:
                    try:
                        # Dynamic prompt based on current mode
                        if self.current_room:
                            prompt_html = f'<ansibrightmagenta>to @{self.current_room} ></ansibrightmagenta> '
                        else:
                            prompt_html = '<ansibrightcyan>></ansibrightcyan> '
                        
                        # Use prompt_toolkit for better input handling
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

                        # Determine targets based on mode
                        if self.current_room:
                            # Private room mode - send only to room user
                            if self.current_room not in self.peer_keys:
                                self.display_message(f"{YELLOW}⚠ User '{self.current_room}' is offline. Leaving room.{RESET}", 'system')
                                self.current_room = None
                                self.show_chat_interface()
                                continue
                            targets = [self.current_room]
                            msg_color = MAGENTA
                            msg_prefix = f"[To {self.current_room}]"
                        else:
                            # Broadcast mode - send to all peers
                            targets = [n for n in self.peer_keys.keys() if n != self.username]
                            if not targets:
                                self.display_message(f"{YELLOW}⚠ No recipients available.{RESET}", 'system')
                                continue
                            msg_color = BLUE
                            msg_prefix = "[You]"

                        try:
                            # Properly encode message with error handling for emojis
                            message_bytes = message.encode('utf-8', errors='surrogatepass')
                        except Exception as e:
                            self.display_message(f"{RED}⚠ Could not encode message: {e}{RESET}", 'error')
                            continue

                        # Display the formatted message with timestamp
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
        """Display chat interface."""
        self.clear_screen()
        
        # Choose theme based on mode
        if self.current_room:
            # Private room mode - MAGENTA/RED theme
            theme_color = MAGENTA
            border_color = RED
            mode_text = f"PRIVATE CHAT with {self.current_room}"
            mode_indicator = f"{RED}[PRIVATE ROOM: {self.current_room}]{RESET}"
        else:
            # Broadcast mode - CYAN/BLUE theme
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
        print_formatted_text(ANSI(f"  {theme_color}/history [count]{RESET}    View message history"))
        print_formatted_text(ANSI(f"  {theme_color}/users{RESET}              List online users"))
        print_formatted_text(ANSI(f"  {theme_color}/clear{RESET}              Clear screen"))
        print_formatted_text(ANSI(f"  {theme_color}/help{RESET}               Show help"))
        print_formatted_text(ANSI(f"  {theme_color}/exit{RESET}               Exit chat"))
        print_formatted_text(ANSI(""))
        print_formatted_text(ANSI(f"{GRAY}{'─' * 70}{RESET}"))
        print_formatted_text(ANSI(""))

    def handle_command(self, message):
        """Handle commands."""
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
            
            # Send room invitation to target
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
            # Accept pending room invitation
            with self.invite_lock:
                if not self.pending_invite:
                    print_formatted_text(ANSI(f"{YELLOW}⚠ No pending room invitation.{RESET}"))
                    return
                
                invite_id = self.pending_invite['invite_id']
                sender = self.pending_invite['from']
            
            # Send acceptance to server
            send_json(self.client_socket, {
                'type': 'room_invite_response',
                'invite_id': invite_id,
                'accepted': True
            })
            
            print_formatted_text(ANSI(f"{GREEN}✓ Accepting room invitation from {sender}...{RESET}\n"))
        
        elif command == '/decline':
            # Decline pending room invitation
            with self.invite_lock:
                if not self.pending_invite:
                    print_formatted_text(ANSI(f"{YELLOW}⚠ No pending room invitation.{RESET}"))
                    return
                
                invite_id = self.pending_invite['invite_id']
                sender = self.pending_invite['from']
            
            # Send rejection to server
            send_json(self.client_socket, {
                'type': 'room_invite_response',
                'invite_id': invite_id,
                'accepted': False
            })
            
            print_formatted_text(ANSI(f"{YELLOW}✗ Declined room invitation from {sender}.{RESET}\n"))
            
            # Clear pending invite
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
            # Display message history
            count = 20  # Default to last 20 messages
            if len(parts) > 1:
                try:
                    count = int(parts[1])
                    count = min(count, 100)  # Max 100 messages
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
            # Determine theme color
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
                        # Highlight current room user
                        if user == self.current_room:
                            print_formatted_text(ANSI(f"  {theme_color}{i}.{RESET} {user} {MAGENTA}(in room){RESET}"))
                        else:
                            print_formatted_text(ANSI(f"  {theme_color}{i}.{RESET} {user}"))
                print_formatted_text(ANSI(""))
                
        elif command == '/clear':
            self.show_chat_interface()
            
        elif command == '/exit':
            self.running = False
            
        else:
            print_formatted_text(ANSI(f"{YELLOW}Unknown command. Type /help for available commands.{RESET}"))

    def encrypt_and_send_message(self, plaintext, targets):
        """Encrypt and send message."""
        aes_key = get_random_bytes(32)
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)
        nonce = aes_cipher.nonce
        
        keys_map = {}
        for target in targets:
            pub = self.peer_keys.get(target)
            if not pub:
                continue
            rsa_cipher = PKCS1_OAEP.new(pub)
            enc_key = rsa_cipher.encrypt(aes_key)
            keys_map[target] = base64.b64encode(enc_key).decode('utf-8')
            
        if not keys_map:
            return
            
        envelope = {
            "type": "encrypted_send",
            "from": self.username,
            "targets": list(keys_map.keys()),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "keys": keys_map
        }
        
        send_json(self.client_socket, envelope)

    def receive_messages(self):
        """Handle incoming messages."""
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
                        
                        # Decode the message
                        message_text = plaintext.decode('utf-8')
                        
                        # Detect if user is mentioned
                        mentions = self.detect_mentions(message_text)
                        is_mentioned = self.username in mentions
                        
                        # Highlight mentions in the message
                        highlighted_text = self.highlight_mentions(message_text, self.username)
                        
                        timestamp = datetime.now().strftime("%H:%M")
                        
                        # Build the message display with mention notification
                        if is_mentioned:
                            # User is mentioned - show special indicator and use highlighted text
                            if is_private:
                                msg = f"{GRAY}[{timestamp}] {YELLOW}{BOLD}[{sender}]-(priv)(@mentioned you){RESET} {highlighted_text}"
                            else:
                                msg = f"{GRAY}[{timestamp}] {YELLOW}{BOLD}[{sender}](@mentioned you){RESET} {highlighted_text}"
                        else:
                            # Normal message with mention highlighting
                            if is_private:
                                msg = f"{GRAY}[{timestamp}] {GREEN}[{sender}]-(priv){RESET} {highlighted_text}"
                            else:
                                msg = f"{GRAY}[{timestamp}] {GREEN}[{sender}]{RESET} {highlighted_text}"
                        
                        self.display_message(msg, 'incoming')
                        
                    except Exception:
                        msg = f"{RED}⚠ Decrypt failed from {sender}{RESET}"
                        self.display_message(msg, 'error')

                elif ptype == 'error':
                    msg = f"{RED}⚠ Server: {pkg.get('msg')}{RESET}"
                    self.display_message(msg, 'error')
                
                # Handle room invitation request
                elif ptype == 'room_invite_request':
                    sender = pkg.get('from')
                    invite_id = pkg.get('invite_id')
                    
                    print(f"\n{BLUE}[DEBUG]{RESET} Received room invite from {sender}, invite_id: {invite_id}")
                    
                    # Store pending invite
                    with self.invite_lock:
                        self.pending_invite = {
                            'from': sender,
                            'invite_id': invite_id
                        }
                    
                    # Display invitation notification (non-blocking)
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
                
                # Handle room invitation accepted
                elif ptype == 'room_accepted':
                    partner = pkg.get('partner')
                    
                    # Enter private room
                    self.current_room = partner
                    self.show_chat_interface()
                    
                    print_formatted_text(ANSI(f"{GREEN}{BOLD}✓ Private room created with {partner}!{RESET}"))
                    print_formatted_text(ANSI(f"{GRAY}  All messages will now be sent only to {partner}.{RESET}"))
                    print_formatted_text(ANSI(f"{GRAY}  Type /leave to return to broadcast mode.{RESET}\n"))
                    
                    # Clear pending invite
                    with self.invite_lock:
                        self.pending_invite = None
                
                # Handle room invitation rejected
                elif ptype == 'room_rejected':
                    user = pkg.get('user')
                    
                    print_formatted_text(ANSI(f"\n{RED}✗ {user} declined your room invitation.{RESET}\n"))
                
                # Handle room invitation failed
                elif ptype == 'room_invite_failed':
                    reason = pkg.get('reason', 'Unknown error')
                    
                    print_formatted_text(ANSI(f"\n{RED}✗ Room invitation failed: {reason}{RESET}\n"))

            except Exception:
                if self.running:
                    break

    def stop(self):
        """Stop client."""
        self.running = False
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        print(f"{BLUE}Connection closed{RESET}")

    def add_to_history(self, message, msg_type='info'):
        """Add message to history buffer."""
        with self.history_lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.message_history.append({
                'timestamp': timestamp,
                'message': message,
                'type': msg_type
            })
    
    def detect_mentions(self, text):
        """
        Detect @mentions in a message.
        Returns list of mentioned usernames.
        """
        import re
        # Match @username (alphanumeric, underscore, hyphen)
        mentions = re.findall(r'@([a-zA-Z0-9_-]+)', text)
        return list(set(mentions))  # Remove duplicates
    
    def highlight_mentions(self, text, my_username):
        """
        Highlight @mentions in text.
        If user is mentioned, highlight their name in YELLOW BOLD.
        Other mentions are highlighted in CYAN.
        """
        import re
        
        def replace_mention(match):
            username = match.group(1)
            if username.lower() == my_username.lower():
                # User is mentioned - highlight in YELLOW BOLD
                return f"{YELLOW}{BOLD}@{username}{RESET}"
            else:
                # Someone else mentioned - highlight in CYAN
                return f"{CYAN}@{username}{RESET}"
        
        return re.sub(r'@([a-zA-Z0-9_-]+)', replace_mention, text)
    
    def display_message(self, message, msg_type='info'):
        """Display a message and add to history."""
        self.add_to_history(message, msg_type)
        
        # Use prompt_toolkit's print for proper ANSI handling on Windows
        print_formatted_text(ANSI(message))

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Unicast Secure Messenger Client')
        parser.add_argument('--host', '-H', default='localhost',
                            help='Server address (default: localhost)')
        parser.add_argument('--port', '-P', type=int, default=1315,
                            help='Server port (default: 1315)')
        args = parser.parse_args()

        client = Client(host=args.host, port=args.port)
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