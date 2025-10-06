import socket
import threading
import json
import base64
import struct

RED = "\033[91;1m"
GREEN = "\033[92;1m"
BLUE = "\033[94;1m"
RESET = "\033[0m"

class TCPserver:
    def __init__(self, host="0.0.0.0", port=1315):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.clients = {}  # name -> {"socket": sock, "pubkey": pubkey_bytes}
        self.lock = threading.Lock()

    # Length-prefixed JSON helpers
    def send_json(self, sock, obj):
        data = json.dumps(obj).encode('utf-8')
        header = struct.pack('>I', len(data))
        sock.sendall(header + data)

    def recv_json(self, sock):
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
        try:
            return json.loads(data.decode('utf-8'))
        except Exception:
            return None

    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            print(f"{GREEN}[+]{RESET} Server started on {self.host}, port {self.port}")

            while self.running:
                client_socket, client_address = self.server_socket.accept()
                print(f"{BLUE}[+]{RESET} New connection from {client_address}!")
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
        except Exception as e:
            print(f"{RED}[x]{RESET} Server error: {e}")
        finally:
            self.stop()

    def handle_client(self, client_socket):
        client_name = None
        try:
            # Receive name_announce
            msg = self.recv_json(client_socket)
            if not msg or msg.get("type") != "name_announce" or 'name' not in msg:
                client_socket.close()
                return
            client_name = msg['name']

            # Receive pubkey_announce
            msg = self.recv_json(client_socket)
            if not msg or msg.get("type") != "pubkey_announce" or msg.get('name') != client_name:
                client_socket.close()
                return
            try:
                pubkey_bytes = base64.b64decode(msg['pubkey'])
            except Exception:
                client_socket.close()
                return

            # Register client
            with self.lock:
                if client_name in self.clients:
                    self.send_json(client_socket, {"type":"error","msg":"__NAME_TAKEN__"})
                    client_socket.close()
                    return
                self.clients[client_name] = {"socket": client_socket, "pubkey": pubkey_bytes}

                # Send all existing clients' pubkeys to the new client
                for other, info in self.clients.items():
                    if other != client_name:
                        try:
                            self.send_json(client_socket, {
                                "type": "pubkey_announce",
                                "name": other,
                                "pubkey": base64.b64encode(info['pubkey']).decode('utf-8')
                            })
                        except:
                            pass

                # Broadcast this new client's pubkey to everyone else
                announce = {
                    "type": "pubkey_announce",
                    "name": client_name,
                    "pubkey": base64.b64encode(pubkey_bytes).decode('utf-8')
                }
                for other, info in self.clients.items():
                    if other != client_name:
                        try:
                            self.send_json(info['socket'], announce)
                        except:
                            pass

            print(f"{BLUE}[+]{RESET} {client_name} connected!")

            # Main loop
            while True:
                pkg = self.recv_json(client_socket)
                if pkg is None:
                    break

                if pkg.get('type') == 'encrypted_send':
                    from_name = pkg.get('from')
                    ciphertext = pkg.get('ciphertext')
                    nonce = pkg.get('nonce')
                    tag = pkg.get('tag')
                    keys_map = pkg.get('keys')
                    targets = pkg.get('targets', [])

                    for target in targets:
                        if target in self.clients:
                            deliver = {
                                'type': 'encrypted_deliver',
                                'from': from_name,
                                'ciphertext': ciphertext,
                                'nonce': nonce,
                                'tag': tag,
                                'key': keys_map[target]
                            }
                            try:
                                self.send_json(self.clients[target]['socket'], deliver)
                            except:
                                pass
                        else:
                            err = {"type":"error","msg":f"User {target} not found."}
                            try:
                                self.send_json(self.clients[from_name]['socket'], err)
                            except:
                                pass

        except Exception as e:
            print(f"{RED}[x]{RESET} Error handling client {client_name}: {e}")
        finally:
            if client_name and client_name in self.clients:
                with self.lock:
                    del self.clients[client_name]
            try:
                client_socket.close()
            except:
                pass
            print(f"{RED}[x]{RESET} Connection closed for {client_name}.")

    def stop(self):
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

if __name__ == "__main__":
    try:
        server = TCPserver()
        server.start()
    except KeyboardInterrupt:
        server.stop()