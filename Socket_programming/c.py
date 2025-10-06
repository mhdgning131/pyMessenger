import socket  # For creating network connections
import threading  # For handling sending/receiving in parallel (multithreading)
import random

# Terminal color codes for pretty output
RED = "\033[91;1m"
GREEN = "\033[92;1m"
BLUE = "\033[94;1m"
RESET = "\033[0m"


# Define the Client class
class Client:
    def __init__(self, host="", port=1315, name=None):
        self.host = host  # Server IP address
        self.port = port  # Server port number
        self.name = name  # name for the client
        self.client_socket = None  # Socket object for communication
        self.running = False  # Flag to keep the client running

    # Start the client
    def start(self):

        name = input("Enter your name: ").lower().strip()
        if not name:
            name = f"User{random.randint(1000, 9999)}"
        self.name = name

        try:
            # Create a TCP socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Connect to the server
            self.client_socket.connect((self.host, self.port))
            self.running = True  # Mark client as running

            print(f"[{GREEN}+{RESET}] Connected to server at {self.host}:{self.port}")

            # send name immediately after connection
            self.client_socket.send(self.name.encode("utf-8"))  # send name to server

            # Start a thread to receive messages from server
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True  # Thread closes when main thread exits
            receive_thread.start()

            # Main loop for sending messages
            while self.running:
                try:
                    # User input for message
                    message = input()

                    # If user wants to quit
                    if message.lower() in ["quit", "exit", "break"]:
                        break

                    # Send the message to the server
                    self.client_socket.send(message.encode("utf-8"))

                except KeyboardInterrupt:
                    # Handle Ctrl+C gracefully
                    print(f"\n[{RED}!{RESET}] Interrupted by user")
                    break
                except Exception as e:
                    # Handle other send errors
                    print(f"[{RED}!{RESET}] Error sending message: {e}")
                    break

        # Handle error if server is unreachable
        except ConnectionRefusedError:
            print(
                f"[{RED}!{RESET}] Could not connect to server at {self.host}:{self.port}"
            )
        except Exception as e:
            print(f"[{RED}!{RESET}] Client error: {e}")
        finally:
            # Cleanly stop the client
            self.stop()

    # Method to receive messages from the server
    def receive_messages(self):
        while self.running:
            try:
                # Receive message (max 1024 bytes)
                response = self.client_socket.recv(1024)

                if not response:
                    # If server closes the connection
                    print(f"[{RED}!{RESET}] Server disconnected")
                    self.running = False
                    break

                # Decode and display the message
                message = response.decode("utf-8")
                print(f">[{BLUE}{message}{RESET}]")

            except Exception as e:
                if self.running:
                    print(f"[{RED}!{RESET}] Error receiving message: {e}")
                break

    # Method to stop the client and close socket
    def stop(self):
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()  # Close the socket connection
            except:
                pass
            print(f"[{BLUE}+{RESET}] Connection closed")


# Run the client
if __name__ == "__main__":
    client = Client()  # Create a Client instance
    client.start()  # Start the client
