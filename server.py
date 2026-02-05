import socket
import threading
import json
import base64
import struct
import traceback
import secrets
import time
import ssl
from pathlib import Path
from user_store import UserStore

RED = "\033[91;1m"
GREEN = "\033[92;1m"
BLUE = "\033[94;1m"
YELLOW = "\033[93;1m"
RESET = "\033[0m"

class Server:
    def __init__(self, host="0.0.0.0", port=1315):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.clients = {}  # session_token -> {"name": name, "socket": sock, "pubkey": pubkey_bytes}
        self.user_store = UserStore()
        self.sessions = {}  # session_token -> {"username": name, "expires": timestamp}
        self.lock = threading.Lock()
        
        # Room invitation tracking
        self.pending_room_invites = {}  # invite_id -> {"from": username, "to": username, "timestamp": time}
        
        # Session timeout: 24 hours
        self.SESSION_TIMEOUT = 86400
        
        # SSL/TLS setup
        self.ssl_context = self._setup_ssl()

    def _setup_ssl(self):
        """Setup SSL/TLS context for secure connections."""
        cert_dir = Path.home() / '.secure_messenger' / 'certs'
        cert_file = cert_dir / 'server.crt'
        key_file = cert_dir / 'server.key'
        
        # Check if certificates exist, if not, generate them
        if not cert_file.exists() or not key_file.exists():
            print(f"{YELLOW}[!]{RESET} SSL certificates not found. Generating...")
            from generate_certificates import generate_self_signed_cert
            try:
                generate_self_signed_cert(cert_dir)
            except Exception as e:
                print(f"{RED}[x]{RESET} Failed to generate certificates: {e}")
                print(f"{YELLOW}[!]{RESET} Server will run without SSL encryption")
                return None
        
        try:
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            
            # Security settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            print(f"{GREEN}[+]{RESET} SSL/TLS encryption enabled")
            print(f"{BLUE}[i]{RESET} Using certificate: {cert_file}")
            return context
        except Exception as e:
            print(f"{RED}[x]{RESET} SSL setup error: {e}")
            print(f"{YELLOW}[!]{RESET} Server will run without SSL encryption")
            return None

    def send_json(self, sock, obj):
        """Send JSON object with length prefix."""
        try:
            data = json.dumps(obj).encode('utf-8')
            header = struct.pack('>I', len(data))
            sock.sendall(header + data)
            return True
        except Exception as e:
            print(f"{RED}[x]{RESET} Error sending JSON: {e}")
            return False

    def recv_json(self, sock):
        """Receive JSON object with length prefix."""
        try:
            header = b''
            while len(header) < 4:
                chunk = sock.recv(4 - len(header))
                if not chunk:
                    return None
                header += chunk
            length = struct.unpack('>I', header)[0]
            data = b''
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            return json.loads(data.decode('utf-8'))
        except ConnectionResetError:
            return None
        except json.JSONDecodeError:
            print(f"{RED}[x]{RESET} Invalid JSON received")
            return None
        except Exception as e:
            print(f"{RED}[x]{RESET} Error receiving JSON: {e}")
            return None
    def generate_session_token(self):
        """Generate a cryptographically secure session token."""
        return secrets.token_urlsafe(32)

    def validate_session(self, token):
        """Validate a session token and return username if valid."""
        with self.lock:
            session = self.sessions.get(token)
            if not session:
                return None
            
            # Check if session has expired
            if time.time() > session['expires']:
                del self.sessions[token]
                return None
            
            return session['username']

    def create_session(self, username):
        """Create a new session for a user."""
        token = self.generate_session_token()
        with self.lock:
            self.sessions[token] = {
                'username': username,
                'expires': time.time() + self.SESSION_TIMEOUT
            }
        return token

    def handle_auth(self, client_socket, client_address):
        """Handle authentication handshake."""
        try:
            # Receive auth request
            auth_msg = self.recv_json(client_socket)
            if not auth_msg or auth_msg.get('type') != 'auth_request':
                self.send_json(client_socket, {
                    'type': 'auth_response',
                    'success': False,
                    'message': 'Invalid authentication request'
                })
                return None, None

            auth_type = auth_msg.get('auth_type')
            
            if auth_type == 'register':
                return self.handle_registration(client_socket, auth_msg)
            elif auth_type == 'login':
                return self.handle_login_challenge(client_socket, auth_msg, client_address)
            else:
                self.send_json(client_socket, {
                    'type': 'auth_response',
                    'success': False,
                    'message': 'Unknown authentication type'
                })
                return None, None

        except Exception as e:
            print(f"{RED}[x]{RESET} Auth error: {e}")
            return None, None

    def handle_registration(self, client_socket, auth_msg):
        """Handle user registration."""
        username = auth_msg.get('username')
        password = auth_msg.get('password')
        pubkey_b64 = auth_msg.get('pubkey')

        if not username or not password or not pubkey_b64:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': 'Missing registration credentials'
            })
            return None, None

        try:
            pubkey_bytes = base64.b64decode(pubkey_b64)
        except Exception:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': 'Invalid public key format'
            })
            return None, None

        # Create user in database
        success, message = self.user_store.create_user_with_pubkey(
            username, password, pubkey_bytes
        )

        if not success:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': message
            })
            return None, None

        # Create session
        token = self.create_session(username)
        
        self.send_json(client_socket, {
            'type': 'auth_response',
            'success': True,
            'message': 'Registration successful',
            'session_token': token
        })

        print(f"{GREEN}[+]{RESET} New user registered: {username}")
        return username, pubkey_bytes

    def handle_login_challenge(self, client_socket, auth_msg, client_address):
        """Handle challenge-response login."""
        username = auth_msg.get('username')
        pubkey_b64 = auth_msg.get('pubkey')

        if not username or not pubkey_b64:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': 'Missing login credentials'
            })
            return None, None

        # Check if user exists
        if username not in self.user_store.users_db:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': 'Invalid username or password.'
            })
            return None, None

        # Step 1: Create and send challenge
        result = self.user_store.create_challenge(username)
        if not result or result[0] is None:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': 'Invalid username or password.'
            })
            return None, None
        
        nonce, salt = result  # Unpack both values
        
        self.send_json(client_socket, {
            'type': 'auth_challenge',
            'nonce': nonce,
            'salt': salt  # Send the salt to the client
        })

        # Step 2: Wait for challenge response
        response_msg = self.recv_json(client_socket)
        if not response_msg or response_msg.get('type') != 'auth_response':
            self.send_json(client_socket, {
                'type': 'auth_result',
                'success': False,
                'message': 'Invalid response format'
            })
            return None, None

        challenge_response = response_msg.get('response')
        if not challenge_response:
            self.send_json(client_socket, {
                'type': 'auth_result',
                'success': False,
                'message': 'Missing challenge response'
            })
            return None, None

        # Step 3: Verify the challenge response
        ip_address = client_address[0] if client_address else None
        success, message = self.user_store.verify_challenge_response(
            username, challenge_response, ip_address
        )

        if not success:
            self.send_json(client_socket, {
                'type': 'auth_result',
                'success': False,
                'message': message
            })
            return None, None

        # Step 4: Verify public key matches
        try:
            pubkey_bytes = base64.b64decode(pubkey_b64)
            stored_pubkey = base64.b64decode(
                self.user_store.users_db[username]['public_key']
            )
            if pubkey_bytes != stored_pubkey:
                send_json(client_socket, {
                    'type': 'auth_result',
                    'success': False,
                    'message': 'Public key mismatch'
                })
                return None, None
        except Exception as e:
            print(f"{RED}[x]{RESET} Key verification error: {e}")
            send_json(client_socket, {
                'type': 'auth_result',
                'success': False,
                'message': 'Invalid public key'
            })
            return None, None

        # Step 5: Create session and send success
        token = self.create_session(username)
        send_json(client_socket, {
            'type': 'auth_result',
            'success': True,
            'message': 'Login successful',
            'session_token': token
        })

        print(f"{GREEN}[+]{RESET} User logged in (challenge-response): {username} from {ip_address}")
        return username, pubkey_bytes

    def start(self):
        """Start the server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)
            
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"{GREEN}[+]{RESET} Server started on {self.host}, port {self.port}")
            if self.ssl_context:
                print(f"{GREEN}[+]{RESET} SSL/TLS encryption: ENABLED")
            else:
                print(f"{YELLOW}[!]{RESET} SSL/TLS encryption: DISABLED (insecure)")
            print(f"{BLUE}[i]{RESET} Authentication system ready")
            print(f"{YELLOW}[i]{RESET} Press Ctrl+C to stop the server")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Wrap socket with SSL if enabled
                    if self.ssl_context:
                        try:
                            client_socket = self.ssl_context.wrap_socket(
                                client_socket,
                                server_side=True
                            )
                            print(f"{BLUE}[+]{RESET} Secure connection from {client_address}")
                        except ssl.SSLError as e:
                            print(f"{RED}[x]{RESET} SSL handshake failed: {e}")
                            client_socket.close()
                            continue
                    else:
                        print(f"{BLUE}[+]{RESET} New connection from {client_address}")
                    
                    threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"{RED}[x]{RESET} Error accepting connection: {e}")
        except Exception as e:
            print(f"{RED}[x]{RESET} Server error: {e}")
        finally:
            self.stop()

    def handle_client(self, client_socket, client_address):
        """Handle client connection."""
        client_name = None
        session_token = None
        
        try:
            # Handle authentication
            client_name, pubkey_bytes = self.handle_auth(client_socket, client_address)
            
            if not client_name or not pubkey_bytes:
                client_socket.close()
                return

            # Check if user already connected
            with self.lock:
                for token, info in self.clients.items():
                    if info['name'] == client_name:
                        print(f"{YELLOW}[!]{RESET} User {client_name} already connected")
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': 'User already connected'
                        })
                        client_socket.close()
                        return

                # Generate session token for this connection
                session_token = self.generate_session_token()
                self.clients[session_token] = {
                    'name': client_name,
                    'socket': client_socket,
                    'pubkey': pubkey_bytes
                }

                # Send existing clients to new client
                for token, info in self.clients.items():
                    if token != session_token:
                        try:
                            self.send_json(client_socket, {
                                'type': 'pubkey_announce',
                                'name': info['name'],
                                'pubkey': base64.b64encode(info['pubkey']).decode('utf-8')
                            })
                        except Exception as e:
                            print(f"{RED}[x]{RESET} Error sending key: {e}")

                # Broadcast new client to existing clients
                announce = {
                    'type': 'pubkey_announce',
                    'name': client_name,
                    'pubkey': base64.b64encode(pubkey_bytes).decode('utf-8')
                }
                
                for token, info in self.clients.items():
                    if token != session_token:
                        try:
                            self.send_json(info['socket'], announce)
                        except Exception as e:
                            print(f"{RED}[x]{RESET} Error announcing: {e}")

            print(f"{GREEN}[+]{RESET} {client_name} ready for messaging")

            # Main message loop
            while True:
                pkg = self.recv_json(client_socket)
                if pkg is None:
                    print(f"{YELLOW}[!]{RESET} Client {client_name} disconnected")
                    break

                ptype = pkg.get('type')
                
                if ptype == 'room_invite':
                    target_user = pkg.get('target')
                    
                    print(f"{BLUE}[i]{RESET} Room invite request from {client_name} to {target_user}")
                    
                    invite_id = self.generate_session_token()
                    
                    with self.lock:
                        # Là on Check if target est online
                        target_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == target_user:
                                target_socket = info['socket']
                                break
                        
                        if target_socket:
                            # Store pending invite
                            self.pending_room_invites[invite_id] = {
                                'from': client_name,
                                'to': target_user,
                                'timestamp': time.time()
                            }
                            
                            # Send invite to target user
                            success = self.send_json(target_socket, {
                                'type': 'room_invite_request',
                                'from': client_name,
                                'invite_id': invite_id
                            })
                            
                            if success:
                                print(f"{GREEN}[✓]{RESET} Room invite sent: {client_name} -> {target_user}")
                            else:
                                print(f"{RED}[x]{RESET} Failed to send invite to {target_user}")
                        else:
                            # Target not online
                            print(f"{YELLOW}[!]{RESET} Target user {target_user} not found")
                            self.send_json(client_socket, {
                                'type': 'room_invite_failed',
                                'reason': 'User not online'
                            })
                
                # Handle room invitation response
                elif ptype == 'room_invite_response':
                    invite_id = pkg.get('invite_id')
                    accepted = pkg.get('accepted')
                    
                    with self.lock:
                        invite = self.pending_room_invites.get(invite_id)
                        
                        if invite and invite['to'] == client_name:
                            inviter = invite['from']
                            
                            # Find inviter's socket
                            inviter_socket = None
                            for token, info in self.clients.items():
                                if info['name'] == inviter:
                                    inviter_socket = info['socket']
                                    break
                            
                            if accepted:
                                # Both users accept - notify both to enter room
                                if inviter_socket:
                                    self.send_json(inviter_socket, {
                                        'type': 'room_accepted',
                                        'partner': client_name
                                    })
                                
                                self.send_json(client_socket, {
                                    'type': 'room_accepted',
                                    'partner': inviter
                                })
                                
                                print(f"{GREEN}[+]{RESET} Room created: {inviter} <-> {client_name}")
                            else:
                                # Invite rejected
                                if inviter_socket:
                                    self.send_json(inviter_socket, {
                                        'type': 'room_rejected',
                                        'user': client_name
                                    })
                                
                                print(f"{YELLOW}[!]{RESET} Room invite rejected: {inviter} -> {client_name}")
                            
                            # Remove pending invite
                            del self.pending_room_invites[invite_id]

                elif ptype == 'encrypted_send':
                    from_name = pkg.get('from')
                    
                    if from_name != client_name:
                        print(f"{RED}[!]{RESET} Identity mismatch from {client_name}")
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': 'Identity mismatch'
                        })
                        continue
                    
                    # Forward encrypted message
                    ciphertext = pkg.get('ciphertext')
                    nonce = pkg.get('nonce')
                    tag = pkg.get('tag')
                    keys_map = pkg.get('keys')
                    targets = pkg.get('targets', [])
                    
                    # Determine if this is a private message (only 1 target)
                    is_private = len(targets) == 1

                    for target in targets:
                        target_found = False
                        with self.lock:
                            for token, info in self.clients.items():
                                if info['name'] == target:
                                    deliver = {
                                        'type': 'encrypted_deliver',
                                        'from': from_name,
                                        'ciphertext': ciphertext,
                                        'nonce': nonce,
                                        'tag': tag,
                                        'key': keys_map[target],
                                        'is_private': is_private  # Add private chat indicator
                                    }
                                    try:
                                        self.send_json(info['socket'], deliver)
                                        target_found = True
                                    except Exception as e:
                                        print(f"{RED}[x]{RESET} Error delivering: {e}")
                                    break
                        
                        if not target_found:
                            self.send_json(client_socket, {
                                'type': 'error',
                                'msg': f'User {target} not found'
                            })
                
                # Handle file offer - relay to target user
                elif ptype == 'file_offer':
                    target = pkg.get('target')
                    filename = pkg.get('filename')
                    filesize = pkg.get('filesize')
                    file_id = pkg.get('file_id')
                    
                    print(f"{BLUE}[i]{RESET} File offer from {client_name} to {target}: {filename} ({filesize} bytes)")
                    
                    with self.lock:
                        # Find target user socket
                        target_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == target:
                                target_socket = info['socket']
                                break
                        
                        if target_socket:
                            # Forward file offer to target
                            success = self.send_json(target_socket, {
                                'type': 'file_offer',
                                'from': client_name,
                                'filename': filename,
                                'filesize': filesize,
                                'file_id': file_id
                            })
                            
                            if success:
                                print(f"{GREEN}[✓]{RESET} File offer relayed to {target}")
                            else:
                                print(f"{RED}[x]{RESET} Failed to relay file offer to {target}")
                                # Notify sender
                                self.send_json(client_socket, {
                                    'type': 'file_offer_failed',
                                    'file_id': file_id,
                                    'reason': 'Failed to contact recipient'
                                })
                        else:
                            print(f"{YELLOW}[!]{RESET} Target user {target} not found")
                            # Notify sender that target is offline
                            self.send_json(client_socket, {
                                'type': 'file_offer_failed',
                                'file_id': file_id,
                                'reason': 'User not online'
                            })
                
                # Handle file response (accept/reject)
                elif ptype == 'file_response':
                    file_id = pkg.get('file_id')
                    accepted = pkg.get('accepted')
                    sender = pkg.get('sender')  # Original sender of the file
                    
                    print(f"{BLUE}[i]{RESET} File response from {client_name}: {'Accepted' if accepted else 'Rejected'} (file_id: {file_id})")
                    
                    with self.lock:
                        # Find sender's socket
                        sender_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == sender:
                                sender_socket = info['socket']
                                break
                        
                        if sender_socket:
                            # Forward response to sender
                            self.send_json(sender_socket, {
                                'type': 'file_response',
                                'file_id': file_id,
                                'accepted': accepted,
                                'recipient': client_name
                            })
                            
                            print(f"{GREEN}[✓]{RESET} File response relayed to {sender}")
                        else:
                            print(f"{YELLOW}[!]{RESET} Sender {sender} not found")
                
                # Handle file transfer - relay encrypted chunks
                elif ptype == 'file_transfer':
                    target = pkg.get('target')
                    file_id = pkg.get('file_id')
                    chunk_num = pkg.get('chunk_num')
                    total_chunks = pkg.get('total_chunks')
                    encrypted_chunk = pkg.get('encrypted_chunk')
                    nonce = pkg.get('nonce')
                    tag = pkg.get('tag')
                    encrypted_key = pkg.get('encrypted_key')
                    
                    with self.lock:
                        # Find target socket
                        target_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == target:
                                target_socket = info['socket']
                                break
                        
                        if target_socket:
                            # Forward encrypted chunk
                            self.send_json(target_socket, {
                                'type': 'file_transfer',
                                'from': client_name,
                                'file_id': file_id,
                                'chunk_num': chunk_num,
                                'total_chunks': total_chunks,
                                'encrypted_chunk': encrypted_chunk,
                                'nonce': nonce,
                                'tag': tag,
                                'encrypted_key': encrypted_key
                            })
                            
                            if chunk_num % 10 == 0 or chunk_num == total_chunks:
                                print(f"{BLUE}[→]{RESET} Relaying file chunk {chunk_num}/{total_chunks} from {client_name} to {target}")

        except ConnectionResetError:
            print(f"{YELLOW}[!]{RESET} Connection reset: {client_name or 'unknown'}")
        except Exception as e:
            print(f"{RED}[x]{RESET} Error handling client {client_name}: {e}")
            traceback.print_exc()
        finally:
            if session_token and session_token in self.clients:
                with self.lock:
                    del self.clients[session_token]
            try:
                client_socket.close()
            except:
                pass
            print(f"{RED}[-]{RESET} Connection closed: {client_name or 'unknown'}")

    def stop(self):
        """Stop the server."""
        self.running = False
        
        with self.lock:
            for info in self.clients.values():
                try:
                    info['socket'].close()
                except:
                    pass
            self.clients.clear()
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print(f"{BLUE}[i]{RESET} Server stopped")


if __name__ == "__main__":
    try:
        server = Server()
        server.start()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!]{RESET} Server shutdown requested")
        server.stop()