import socket
import threading
import argparse
import json
import base64
import struct
import traceback
import secrets
import time
import ssl
from pathlib import Path
from user_store import UserStore
from validation import ValidationError, validate_username, validate_password, validate_pubkey, validate_challenge_response, validate_bundle, validate_target_user, validate_invite_id, validate_request_id, validate_message_type, validate_file_size, validate_chunk_size, validate_counter, validate_session_id, validate_file_id, validate_nonce, validate_ciphertext, validate_tag, validate_encrypted_key, validate_ratchet_pub, validate_signature, validate_host, validate_port, validate_ip_address, sanitize_filename

RED = "\033[91;1m"
GREEN = "\033[92;1m"
BLUE = "\033[94;1m"
YELLOW = "\033[93;1m"
RESET = "\033[0m"

class Server:
    def __init__(self, host="0.0.0.0", port=80, certificate_hosts=None):
        self.host = validate_host(host)
        self.port = validate_port(port)
        self.certificate_hosts = certificate_hosts
        self.server_socket = None
        self.running = False
        self.clients = {}                                                                           
        self.user_store = UserStore()
        self.sessions = {}                                                             
        self.lock = threading.Lock()                        
        self.pending_room_invites = {}              
        self.SESSION_TIMEOUT = 86400
        
                       
        self.ssl_context = self._setup_ssl()

    def _setup_ssl(self):
                                                           
        cert_dir = Path.home() / '.secure_messenger' / 'certs'
        
        try:
            from generate_certificates import ensure_certificates
            ca_cert_file, cert_file, key_file = ensure_certificates(cert_dir, self.certificate_hosts)
        except Exception as e:
            print(f"{RED}[x]{RESET} Failed to generate certificates: {e}")
            print(f"{YELLOW}[!]{RESET} Server TLS setup failed")
            return None
        
        try:
                                
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            context.load_verify_locations(cafile=str(ca_cert_file))
            
                               
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            print(f"{GREEN}[+]{RESET} SSL/TLS encryption enabled")
            print(f"{BLUE}[i]{RESET} Using CA-signed certificate: {cert_file}")
            return context
        except Exception as e:
            print(f"{RED}[x]{RESET} SSL setup error: {e}")
            print(f"{YELLOW}[!]{RESET} Server TLS setup failed")
            return None

    def send_json(self, sock, obj):
                                                  
        try:
            data = json.dumps(obj).encode('utf-8')
            header = struct.pack('>I', len(data))
            sock.sendall(header + data)
            return True
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionResetError, BrokenPipeError):
            return False
        except Exception as e:
            print(f"{RED}[x]{RESET} Error sending JSON: {e}")
            return False

    def recv_json(self, sock):
                                                     
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
                                                                
        return secrets.token_urlsafe(32)

    def validate_session(self, token):
                                                                    
        with self.lock:
            session = self.sessions.get(token)
            if not session:
                return None
            
                                          
            if time.time() > session['expires']:
                del self.sessions[token]
                return None
            
            return session['username']

    def create_session(self, username):
                                              
        token = self.generate_session_token()
        with self.lock:
            self.sessions[token] = {
                'username': username,
                'expires': time.time() + self.SESSION_TIMEOUT
            }
        return token

    def handle_auth(self, client_socket, client_address):
        try:
            auth_msg = self.recv_json(client_socket)
            if auth_msg is None:
                return None, None

            try:
                validate_auth_request(auth_msg)
            except ValidationError as e:
                self.send_json(client_socket, {
                    'type': 'auth_response',
                    'success': False,
                    'message': str(e)
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
        try:
            username = validate_username(auth_msg.get('username'))
            password = validate_password(auth_msg.get('password'))
            pubkey_b64 = validate_pubkey(auth_msg.get('pubkey'))
        except ValidationError as e:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': str(e)
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
        try:
            username = validate_username(auth_msg.get('username'))
            pubkey_b64 = validate_pubkey(auth_msg.get('pubkey'))
        except ValidationError as e:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': str(e)
            })
            return None, None

        if username not in self.user_store.users_db:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': 'Invalid username or password.'
            })
            return None, None

        result = self.user_store.create_challenge(username)
        if not result or result[0] is None:
            self.send_json(client_socket, {
                'type': 'auth_response',
                'success': False,
                'message': 'Invalid username or password.'
            })
            return None, None

        nonce, salt = result

        self.send_json(client_socket, {
            'type': 'auth_challenge',
            'nonce': nonce,
            'salt': salt
        })

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

        try:
            validate_challenge_response(challenge_response)
        except ValidationError as e:
            self.send_json(client_socket, {
                'type': 'auth_result',
                'success': False,
                'message': str(e)
            })
            return None, None

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

        try:
            pubkey_bytes = base64.b64decode(pubkey_b64)
            stored_pubkey = base64.b64decode(
                self.user_store.users_db[username]['public_key']
            )
            if pubkey_bytes != stored_pubkey:
                self.send_json(client_socket, {
                    'type': 'auth_result',
                    'success': False,
                    'message': 'Public key mismatch'
                })
                return None, None
        except Exception as e:
            print(f"{RED}[x]{RESET} Key verification error: {e}")
            self.send_json(client_socket, {
                'type': 'auth_result',
                'success': False,
                'message': 'Invalid public key'
            })
            return None, None

        token = self.create_session(username)
        self.send_json(client_socket, {
            'type': 'auth_result',
            'success': True,
            'message': 'Login successful',
            'session_token': token
        })

        print(f"{GREEN}[+]{RESET} User logged in (challenge-response): {username} from {ip_address}")
        return username, pubkey_bytes

    def start(self):
        try:
            if not self.ssl_context:
                print(f"{RED}[x]{RESET} SSL/TLS setup failed. Run generate_certificates.py before starting the server.")
                return

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)
            
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"{GREEN}[+]{RESET} Server started on {self.host}, port {self.port}")
            print(f"{GREEN}[+]{RESET} SSL/TLS encryption: ENABLED")
            print(f"{BLUE}[i]{RESET} Authentication system ready")
            print(f"{YELLOW}[i]{RESET} Press Ctrl+C to stop the server")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
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
                                       
        client_name = None
        session_token = None
        
        try:
                                   
            client_name, pubkey_bytes = self.handle_auth(client_socket, client_address)
            
            if not client_name or not pubkey_bytes:
                client_socket.close()
                return

                                             
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

                                                            
                session_token = self.generate_session_token()
                self.clients[session_token] = {
                    'name': client_name,
                    'socket': client_socket,
                    'pubkey': pubkey_bytes
                }

                                                     
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

                               
            while True:
                pkg = self.recv_json(client_socket)
                if pkg is None:
                    print(f"{YELLOW}[!]{RESET} Client {client_name} disconnected")
                    break

                ptype = pkg.get('type')
                
                if ptype == 'room_invite':
                    try:
                        target_user = validate_target_user(pkg.get('target'))
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': str(e)
                        })
                        continue

                    print(f"{BLUE}[i]{RESET} Room invite request from {client_name} to {target_user}")

                    invite_id = self.generate_session_token()

                    with self.lock:
                        target_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == target_user:
                                target_socket = info['socket']
                                break

                        if target_socket:
                            self.pending_room_invites[invite_id] = {
                                'from': client_name,
                                'to': target_user,
                                'timestamp': time.time()
                            }

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
                            print(f"{YELLOW}[!]{RESET} Target user {target_user} not found")
                            self.send_json(client_socket, {
                                'type': 'room_invite_failed',
                                'reason': 'User not online'
                            })

                elif ptype == 'signal_bundle_upload':
                    bundle = pkg.get('bundle')
                    if not bundle:
                        self.send_json(client_socket, {
                            'type': 'signal_bundle_ack',
                            'success': False,
                            'message': 'Missing Signal bundle'
                        })
                        continue

                    try:
                        validate_bundle(bundle)
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'signal_bundle_ack',
                            'success': False,
                            'message': str(e)
                        })
                        continue

                    with self.lock:
                        success, message = self.user_store.set_signal_bundle(client_name, bundle)

                    self.send_json(client_socket, {
                        'type': 'signal_bundle_ack',
                        'success': success,
                        'message': message
                    })

                    if success:
                        print(f"{GREEN}[+]{RESET} Signal bundle stored for {client_name}")

                elif ptype == 'signal_bundle_request':
                    try:
                        target_user = validate_target_user(pkg.get('target'))
                        request_id = validate_request_id(pkg.get('request_id'))
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'signal_bundle_response',
                            'request_id': pkg.get('request_id', ''),
                            'success': False,
                            'message': str(e)
                        })
                        continue

                    with self.lock:
                        bundle = self.user_store.get_signal_bundle(target_user, consume_one_time=True)

                    if bundle:
                        self.send_json(client_socket, {
                            'type': 'signal_bundle_response',
                            'request_id': request_id,
                            'target': target_user,
                            'success': True,
                            'bundle': bundle
                        })
                    else:
                        self.send_json(client_socket, {
                            'type': 'signal_bundle_response',
                            'request_id': request_id,
                            'target': target_user,
                            'success': False,
                            'message': 'No Signal bundle available for that user'
                        })

                elif ptype == 'signal_send':
                    from_name = pkg.get('from')
                    target = pkg.get('target')
                    packet = pkg.get('packet')

                    if from_name != client_name:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': 'Identity mismatch'
                        })
                        continue

                    try:
                        validate_target_user(target)
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': str(e)
                        })
                        continue

                    if not packet:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': 'Invalid Signal packet'
                        })
                        continue

                    target_socket = None
                    with self.lock:
                        for token, info in self.clients.items():
                            if info['name'] == target:
                                target_socket = info['socket']
                                break

                    if target_socket:
                        try:
                            self.send_json(target_socket, packet)
                        except Exception as e:
                            print(f"{RED}[x]{RESET} Error forwarding Signal packet: {e}")
                    else:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': f'User {target} not found'
                        })
                
                                                 
                elif ptype == 'room_invite_response':
                    try:
                        invite_id = validate_invite_id(pkg.get('invite_id'))
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': str(e)
                        })
                        continue

                    accepted = pkg.get('accepted')

                    with self.lock:
                        invite = self.pending_room_invites.get(invite_id)

                        if invite and invite['to'] == client_name:
                            inviter = invite['from']

                            inviter_socket = None
                            for token, info in self.clients.items():
                                if info['name'] == inviter:
                                    inviter_socket = info['socket']
                                    break

                            if accepted:
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
                                if inviter_socket:
                                    self.send_json(inviter_socket, {
                                        'type': 'room_rejected',
                                        'user': client_name
                                    })

                                print(f"{YELLOW}[!]{RESET} Room invite rejected: {inviter} -> {client_name}")

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

                    try:
                        ciphertext = validate_ciphertext(pkg.get('ciphertext'))
                        nonce = validate_nonce(pkg.get('nonce'))
                        tag = validate_tag(pkg.get('tag'))
                        keys_map = pkg.get('keys')
                        targets = pkg.get('targets', [])
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': str(e)
                        })
                        continue

                    is_private = len(targets) == 1

                    for target in targets:
                        try:
                            validate_target_user(target)
                        except ValidationError as e:
                            self.send_json(client_socket, {
                                'type': 'error',
                                'msg': str(e)
                            })
                            continue

                        target_found = False
                        with self.lock:
                            for token, info in self.clients.items():
                                if info['name'] == target:
                                    deliver = {
                                        'type': 'encrypted_deliver',
                                        'from': from_name,
                                        'ciphertext': pkg.get('ciphertext'),
                                        'nonce': pkg.get('nonce'),
                                        'tag': pkg.get('tag'),
                                        'key': keys_map[target],
                                        'is_private': is_private
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
                
                                                          
                elif ptype == 'file_offer':
                    try:
                        target = validate_target_user(pkg.get('target'))
                        filename = sanitize_filename(pkg.get('filename'))
                        filesize = validate_file_size(pkg.get('filesize'))
                        file_id = validate_file_id(pkg.get('file_id'))
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': str(e)
                        })
                        continue

                    print(f"{BLUE}[i]{RESET} File offer from {client_name} to {target}: {filename} ({filesize} bytes)")

                    with self.lock:
                        target_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == target:
                                target_socket = info['socket']
                                break

                        if target_socket:
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
                                self.send_json(client_socket, {
                                    'type': 'file_offer_failed',
                                    'file_id': file_id,
                                    'reason': 'Failed to contact recipient'
                                })
                        else:
                            print(f"{YELLOW}[!]{RESET} Target user {target} not found")
                            self.send_json(client_socket, {
                                'type': 'file_offer_failed',
                                'file_id': file_id,
                                'reason': 'User not online'
                            })
                
                                                      
                elif ptype == 'file_response':
                    try:
                        file_id = validate_file_id(pkg.get('file_id'))
                        sender = validate_target_user(pkg.get('sender'))
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': str(e)
                        })
                        continue

                    accepted = pkg.get('accepted')

                    print(f"{BLUE}[i]{RESET} File response from {client_name}: {'Accepted' if accepted else 'Rejected'} (file_id: {file_id})")

                    with self.lock:
                        sender_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == sender:
                                sender_socket = info['socket']
                                break

                        if sender_socket:
                            self.send_json(sender_socket, {
                                'type': 'file_response',
                                'file_id': file_id,
                                'accepted': accepted,
                                'recipient': client_name
                            })

                            print(f"{GREEN}[✓]{RESET} File response relayed to {sender}")
                        else:
                            print(f"{YELLOW}[!]{RESET} Sender {sender} not found")
                
                                                               
                elif ptype == 'file_transfer':
                    try:
                        target = validate_target_user(pkg.get('target'))
                        file_id = validate_file_id(pkg.get('file_id'))
                        chunk_num = validate_counter(pkg.get('chunk_num'))
                        total_chunks = validate_counter(pkg.get('total_chunks'))
                        encrypted_chunk = validate_ciphertext(pkg.get('encrypted_chunk'))
                        nonce = validate_nonce(pkg.get('nonce'))
                        tag = validate_tag(pkg.get('tag'))
                        encrypted_key = validate_encrypted_key(pkg.get('encrypted_key'))
                    except ValidationError as e:
                        self.send_json(client_socket, {
                            'type': 'error',
                            'msg': str(e)
                        })
                        continue

                    with self.lock:
                        target_socket = None
                        for token, info in self.clients.items():
                            if info['name'] == target:
                                target_socket = info['socket']
                                break

                        if target_socket:
                            self.send_json(target_socket, {
                                'type': 'file_transfer',
                                'from': client_name,
                                'file_id': file_id,
                                'chunk_num': chunk_num,
                                'total_chunks': total_chunks,
                                'encrypted_chunk': pkg.get('encrypted_chunk'),
                                'nonce': pkg.get('nonce'),
                                'tag': pkg.get('tag'),
                                'encrypted_key': pkg.get('encrypted_key')
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
        parser = argparse.ArgumentParser(description='Unicast Secure Messenger Server')
        parser.add_argument('--host', '-H', default='0.0.0.0',
                            help='Bind address (default: 0.0.0.0)')
        parser.add_argument('--port', '-P', type=int, default=80,
                            help='Listen port (default: 80)')
        parser.add_argument('--cert-host', action='append', dest='cert_hosts',
                            help='Hostname or IP to include in the server certificate SAN. May be repeated.')
        args = parser.parse_args()

        server = Server(host=args.host, port=args.port, certificate_hosts=args.cert_hosts)
        server.start()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!]{RESET} Server shutdown requested")
        server.stop()