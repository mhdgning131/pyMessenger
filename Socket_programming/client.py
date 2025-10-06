import socket
import threading
import json
import base64
import struct
import random

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# Terminal color codes
RED = "\033[91;1m"
GREEN = "\033[92;1m"
BLUE = "\033[94;1m"
RESET = "\033[0m"

# Helpers for length-prefixed JSON transports

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


class Client:
    def __init__(self, host='41.83.102.184', port=1315, name=None):
        self.host = host
        self.port = port
        self.name = name
        self.client_socket = None
        self.running = False
        # peer name -> RSA public key object
        self.peer_keys = {}
        # generate RSA keypair
        self.rsa_key = RSA.generate(2048)
        self.private_key_bytes = self.rsa_key.export_key()
        self.public_key_bytes = self.rsa_key.publickey().export_key()

    def start(self):
        name = input('Enter your name: ').lower().strip()
        if not name:
            name = f'User{random.randint(1000,9999)}'
        self.name = name

        try:
            # Create a TCP socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Connect to the server
            self.client_socket.connect((self.host, self.port))
            self.running = True # Mark client as running
            print(f"[{GREEN}+{RESET}] Connected to server at {self.host}:{self.port}")

            # send name_announce and pubkey_announce
            send_json(self.client_socket, {"type": "name_announce", "name": self.name})
            pubkey_b64 = base64.b64encode(self.public_key_bytes).decode('utf-8')
            send_json(self.client_socket, {"type": "pubkey_announce", "name": self.name, "pubkey": pubkey_b64})

            # start receiver thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True # Thread closes when main thread exits
            receive_thread.start()

            # main input loop
            while self.running:
                try:
                    message = input()
                    if not message:
                        continue
                    if message.lower() in ['quit', 'exit', 'break', 'disconnect']:
                        break

                    # determine targets and plaintext
                    if message.startswith('/msg '):
                        parts = message.split(' ', 2)
                        if len(parts) < 3:
                            print(f"{RED}Invalid /msg usage. Use: /msg <name> <message>{RESET}")
                            continue
                        target = parts[1]
                        plaintext = parts[2].encode('utf-8')
                        targets = [target]
                    else:
                        plaintext = message.encode('utf-8')
                        # broadcast to all known peers except self
                        targets = [n for n in self.peer_keys.keys() if n != self.name]

                    if not targets:
                        print(f"{RED}No recipients available (no peer public keys).{RESET}")
                        continue

                    # AES encrypt once
                    aes_key = get_random_bytes(32)  # AES-256
                    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
                    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)
                    nonce = aes_cipher.nonce

                    # encrypt AES key for each target
                    keys_map = {}
                    for t in targets:
                        pub = self.peer_keys.get(t)
                        if not pub:
                            print(f"{RED}No public key for {t}. Skipping recipient.{RESET}")
                            continue
                        rsa_cipher = PKCS1_OAEP.new(pub)
                        enc_key = rsa_cipher.encrypt(aes_key)
                        keys_map[t] = base64.b64encode(enc_key).decode('utf-8')

                    if not keys_map:
                        print(f"{RED}No recipients could be encrypted for. Aborting send.{RESET}")
                        continue

                    envelope = {
                        "type": "encrypted_send",
                        "from": self.name,
                        "targets": list(keys_map.keys()),
                        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                        "nonce": base64.b64encode(nonce).decode('utf-8'),
                        "tag": base64.b64encode(tag).decode('utf-8'),
                        "keys": keys_map
                    }

                    send_json(self.client_socket, envelope)

                except KeyboardInterrupt:
                    print(f"\n[{RED}!{RESET}] Interrupted by user")
                    break
                except Exception as e:
                    print(f"[{RED}!{RESET}] Error sending message: {e}")
                    break

        except ConnectionRefusedError:
            print(f"[{RED}!{RESET}] Could not connect to server at {self.host}:{self.port}")
        except Exception as e:
            print(f"[{RED}!{RESET}] Client error: {e}")
        finally:
            self.stop()

    def receive_messages(self):
        while self.running:
            try:
                pkg = recv_json(self.client_socket)
                if pkg is None:
                    print(f"[{RED}!{RESET}] Server disconnected")
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
                        print(f"{BLUE}[+]{RESET} Received public key for {name}")
                    except Exception:
                        pass

                elif ptype == 'encrypted_deliver':
                    sender = pkg.get('from')
                    try:
                        enc_key_b64 = pkg.get('key')
                        enc_key = base64.b64decode(enc_key_b64)
                        ciphertext = base64.b64decode(pkg.get('ciphertext'))
                        nonce = base64.b64decode(pkg.get('nonce'))
                        tag = base64.b64decode(pkg.get('tag'))

                        # decrypt AES key with our private key
                        priv = RSA.import_key(self.private_key_bytes)
                        rsa_cipher = PKCS1_OAEP.new(priv)
                        aes_key = rsa_cipher.decrypt(enc_key)

                        # decrypt message
                        aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                        plaintext = aes.decrypt_and_verify(ciphertext, tag)
                        print(f">[{BLUE}{sender}{RESET}] {plaintext.decode('utf-8')}" )
                    except ValueError:
                        print(f"{RED}Message authentication failed or corrupted from {sender}.{RESET}")
                    except Exception as e:
                        print(f"{RED}Error decrypting message: {e}{RESET}")

                elif ptype == 'error':
                    print(f"{RED}Server error: {pkg.get('msg')}{RESET}")

                else:
                    # unknown message types can be ignored or printed
                    pass

            except Exception as e:
                if self.running:
                    print(f"[{RED}!{RESET}] Error receiving message: {e}")
                break

    def stop(self):
        self.running = False
        try:
            if self.client_socket:
                self.client_socket.close()
        except:
            pass
        print(f"{BLUE}+{RESET} Connection closed")


if __name__ == '__main__':
    c = Client()
    c.start()