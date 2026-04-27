# Unicast Secure Messenger

A secure messaging app with end-to-end encryption.

## What it does

- Messages are encrypted end-to-end (server can't read them)
- Secure login without sending passwords
- Send files to other users
- Private chat rooms
- Uses Signal-style encryption

## Getting started

### Requirements
- Python 3.8+
- Install dependencies: `pip install -r requirements.txt`

### Running it

```bash
# Start the server (creates certificates automatically)
python server.py --host 0.0.0.0 --port 1315

# Start a client
python client.py --host localhost --port 1315
```

First time? Register an account when you start the client.

## Commands

- `/room <user>` - Start private chat with someone
- `/leave` - Leave private room
- `/msg <user> <text>` - Send a private message
- `/sendfile <user> <path>` - Send a file
- `/acceptfile [#]` - Accept a file transfer
- `/rejectfile [#]` - Reject a file transfer
- `/users` - See who's online
- `/history [count]` - See past messages
- `/clear` - Clear the screen
- `/help` - Show all commands
- `/exit` - Quit

## Files

Received files go to:
- `~/.secure_messenger_client/files/received/` (Linux/Mac)
- `C:\Users\[User]\.secure_messenger_client\files\received\` (Windows)

## Security stuff

Uses X25519, Ed25519, AES-256-GCM, SHA-256, and PBKDF2. Passwords aren't sent after you register. Messages have replay protection and perfect forward secrecy.

**Note:** This is a learning project, not for serious security use. For real secure messaging, use Signal or Wire.

## Files in the project

```
Unicast v1.0/
├── client.py              # The client app
├── server.py              # The server
├── user_store.py          # User database and login
├── signal_protocol.py     # Encryption stuff
├── generate_certificates.py  # SSL certificates
├── validation.py          # Input checking
├── requirements.txt       # Python packages
└── README.md             # This file
```

## License

MIT

## Author

[Mohamed G.](https://mohamedg.me) - M. M. Sabaly