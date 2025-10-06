import socket  # Module for creating network connections
import threading  # Module for handling multiple clients using threads

# Terminal color codes for colorful output in the terminal
RED = "\033[91;1m"
GREEN = "\033[92;1m"
BLUE = "\033[94;1m"
RESET = "\033[0m"


# TCPserver class to manage the server
class TCPserver:
    def __init__(self, host="localhost", port=1315):
        # Use local IP address automatically
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.clients = {}  # Dictionary mapping client names to sockets

    # Start the server
    def start(self):
        try:
            # Create TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print(
                f"{GREEN}[+]{RESET} Server started on {self.host}, at port {self.port}"
            )

            # Accept connections in a loop
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    print(f"{BLUE}[+]{RESET} New connection from {client_address}!")

                    # Start a thread per client
                    client_thread = threading.Thread(
                        target=self.handleclient, args=(client_address, client_socket)
                    )
                    client_thread.start()

                except socket.error as e:
                    print(f"{RED}[x]{RESET} Error accepting connection: {e}")

        except Exception as e:
            print(f"{RED}[x]{RESET} Server error: {e}")
        finally:
            self.stop()

    # Function to handle a connected client
    def handleclient(self, client_address, client_socket):
        client_name = None

        try:
            # Receive and validate client name
            while True:
                client_name = client_socket.recv(1024).decode("utf-8").strip()

                if client_name in self.clients:
                    client_socket.send("__NAME_TAKEN__".encode("utf-8"))
                else:
                    break

            self.clients[client_name] = client_socket
            print(f"{BLUE}[+]{RESET} {client_name} connected!")

            # Main loop to receive messages
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break  # Client disconnected

                message = data.decode()
                print(f"{BLUE}[+]{RESET} {client_name} says: {message}")

                # Handle private message: /msg target_name message
                if message.startswith("/msg "):
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        client_socket.send(
                            f"{RED}Invalid /msg command. Use: /msg <name> <message>{RESET}".encode(
                                "utf-8"
                            )
                        )
                        continue

                    target_name = parts[1]
                    private_msg = parts[2]

                    if target_name == client_name:
                        client_socket.send(
                            f"{RED}You cannot send a private message to yourself.{RESET}".encode(
                                "utf-8"
                            )
                        )
                        continue

                    if target_name in self.clients:
                        self.clients[target_name].send(
                            f"[PM from {client_name}] {private_msg}".encode("utf-8")
                        )
                        client_socket.send(
                            f"[PM to {BLUE}{target_name}{RESET}] {private_msg}".encode(
                                "utf-8"
                            )
                        )
                    else:
                        client_socket.send(
                            f"{RED}User {target_name} not found.{RESET}".encode("utf-8")
                        )

                else:
                    # Broadcast to everyone except the sender
                    disconnected = []
                    for other_name, other_sock in self.clients.items():
                        if other_sock != client_socket:
                            try:
                                other_sock.send(
                                    f"{BLUE}{client_name}{RESET}: {message}".encode(
                                        "utf-8"
                                    )
                                )
                            except:
                                # Mark unreachable clients
                                disconnected.append(other_name)

                    # Remove disconnected clients
                    for name in disconnected:
                        try:
                            self.clients[name].close()
                        except:
                            pass
                        del self.clients[name]

        except Exception as e:
            print(f"{RED}[x]{RESET} Error handling client {client_name}: {e}")
        finally:
            # Clean up on disconnect
            client_socket.close()
            if client_name in self.clients:
                del self.clients[client_name]
            print(f"{RED}[x]{RESET} Connection closed for client {client_name}.")

    # Stop the server and close all sockets
    def stop(self):
        for sock in self.clients.values():
            try:
                sock.close()
            except:
                pass
        self.clients.clear()
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass


# Start the server if the script is run directly
if __name__ == "__main__":
    try:
        server = TCPserver()
        server.start()
    except KeyboardInterrupt:
        server.stop()
