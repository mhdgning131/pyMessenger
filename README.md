# pyMessenger

**End-to-End Encrypted Messaging System**

A secure, terminal-based messaging application implementing modern cryptographic protocols for private communication.
<img width="720" height="306" alt="image" src="https://github.com/user-attachments/assets/60d51210-5187-4a5a-93b9-29c94fe867cc" />


---

## Overview

pyMessenger is a client-server messaging system that provides end-to-end encryption, secure authentication, and both broadcast and private messaging capabilities. The system uses a hybrid encryption approach combining RSA and AES encryption, with SSL/TLS transport layer security.

---

## Cryptographic Architecture

### Encryption Layers

pyMessenger implements a **defense-in-depth** security model with multiple encryption layers:

```md
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │         End-to-End Message Encryption (E2EE)          │  │
│  │                                                       │  │
│  │  • RSA-2048 for AES key exchange                      │  │
│  │  • AES-256-EAX for message content                    │  │
│  │  • Per-message unique keys                            │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     TRANSPORT LAYER                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            TLS/SSL Encryption (Optional)              │  │
│  │                                                       │  │
│  │  • TLS 1.2+ with strong cipher suites                 │  │
│  │  • Protects metadata and prevents MITM                │  │
│  │  • Certificate-based server verification              │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Key Management

**Client-Side Key Storage:**

Each client generates and stores their RSA keypair locally with password-based encryption:

```md
User Password
     │
     ▼
[PBKDF2-SHA256] ───────────► Encryption Key (256-bit)
100,000 iterations                    │
Random salt (128-bit)                 │
                                      ▼
                              [AES-256-GCM]
                                      │
                                      ▼
                          RSA Private Key (encrypted)
                                      │
                                      ▼
                          ~/.secure_messenger_client/keys/
                              {username}_private.key
```

**Server-Side Storage:**

The server never has access to private keys. It only stores:
- Hashed passwords (PBKDF2-SHA256, 100,000 iterations)
- Public keys (RSA-2048)
- Account metadata

---

## Authentication System

### Challenge-Response Authentication

pyMessenger uses a secure challenge-response protocol that avoids transmitting passwords over the network after initial registration:

```md
┌────────────┐                                    ┌────────────┐
│   CLIENT   │                                    │   SERVER   │
└─────┬──────┘                                    └─────┬──────┘
      │                                                 │
      │  1. Login Request (username + public key)       │
      ├────────────────────────────────────────────────►│
      │                                                 │
      │                                                 │ Generate
      │                                                 │ Random
      │                                                 │ Nonce
      │                                                 │
      │  2. Challenge (nonce + salt)                    │
      │◄────────────────────────────────────────────────┤
      │                                                 │
      │ Derive password key                             │
      │ from password + salt                            │
      │                                                 │
      │ response = HMAC-SHA256(                         │
      │   key=password_key,                             │
      │   msg=nonce                                     │
      │ )                                               │
      │                                                 │
      │  3. Response (HMAC signature)                   │
      ├────────────────────────────────────────────────►│
      │                                                 │
      │                                                 │ Verify
      │                                                 │ HMAC with
      │                                                 │ stored key
      │                                                 │
      │  4. Session Token (if valid)                    │
      │◄────────────────────────────────────────────────┤
      │                                                 │
```

**Security Features:**

1. **No Password Transmission**: Password never sent over network after registration
2. **Replay Protection**: Each nonce is single-use and time-limited (5 minutes)
3. **Salt-Based Key Derivation**: Prevents rainbow table attacks
4. **Constant-Time Comparison**: Prevents timing attacks on response verification
5. **Rate Limiting**: 5 failed attempts trigger 15-minute account lockout

---

## End-to-End Message Encryption

### Hybrid Encryption Scheme

Messages use a hybrid approach combining asymmetric and symmetric encryption:

```md
┌──────────────────────────────────────────────────────────────┐
│                     MESSAGE ENCRYPTION                        │
└──────────────────────────────────────────────────────────────┘

1. GENERATE SYMMETRIC KEY
   ┌────────────────────┐
   │ Random AES-256 Key │  ◄── Cryptographically secure
   └──────────┬─────────┘      random number generator
              │
              ▼
2. ENCRYPT MESSAGE CONTENT
   ┌──────────────┐
   │   Plaintext  │
   └──────┬───────┘
          │
          ▼
   [AES-256-EAX]  ◄── EAX mode provides authentication
          │           (prevents tampering)
          ├─────► Ciphertext
          ├─────► Nonce (96-bit)
          └─────► Authentication Tag (128-bit)

3. ENCRYPT AES KEY FOR EACH RECIPIENT
   ┌──────────────────┐
   │ AES-256 Key      │
   └────────┬─────────┘
            │
            ▼
     [RSA-2048-OAEP] ◄── Using recipient's public key
            │            (Separate encryption per recipient)
            │
            ├─────► Encrypted Key (Recipient A)
            ├─────► Encrypted Key (Recipient B)
            └─────► Encrypted Key (Recipient C)

4. DELIVER MESSAGE ENVELOPE
   {
     "ciphertext": <encrypted message>,
     "nonce": <AES nonce>,
     "tag": <authentication tag>,
     "keys": {
       "recipient_a": <encrypted AES key for A>,
       "recipient_b": <encrypted AES key for B>
     }
   }
```

**Why This Design?**

- **RSA**: Secure key exchange, but too slow for large messages
- **AES**: Fast symmetric encryption for message content
- **EAX Mode**: Provides both encryption and authentication (AEAD)
- **Per-Recipient Keys**: Each recipient gets individually encrypted AES key

### Decryption Process

```
RECIPIENT RECEIVES MESSAGE ENVELOPE
            │
            ▼
1. Extract encrypted AES key for this recipient
            │
            ▼
2. Decrypt AES key using recipient's RSA private key
   [RSA-2048-OAEP Decrypt]
            │
            ▼
3. Decrypt message content with recovered AES key
   [AES-256-EAX Decrypt + Verify]
            │
            ├─────► Verify Authentication Tag
            │       (Ensures message not tampered)
            │
            └─────► Plaintext Message
```

---

## Security Features

### Password Security

| Feature | Implementation |
|---------|----------------|
| **Key Derivation** | PBKDF2-SHA256 with 100,000 iterations |
| **Salt** | 256-bit random salt per password |
| **Storage** | Hashed password (never plaintext) |
| **Transmission** | Password only sent during registration (over TLS) |

### Authentication Security

| Feature | Implementation |
|---------|----------------|
| **Protocol** | Challenge-response (HMAC-based) |
| **Challenge Timeout** | 5 minutes |
| **Rate Limiting** | 5 attempts per 15-minute window |
| **Account Lockout** | 15 minutes after 5 failed attempts |
| **Timing Attack Prevention** | Constant-time comparisons |
| **Username Enumeration Prevention** | Consistent response times |

### Message Security

| Feature | Implementation |
|---------|----------------|
| **Encryption Algorithm** | AES-256 in EAX mode |
| **Key Exchange** | RSA-2048 with OAEP padding |
| **Key Lifetime** | Single-use per message |
| **Authentication** | AEAD with 128-bit tag |

### Transport Security

| Feature | Implementation |
|---------|----------------|
| **Protocol** | TLS 1.2+ |
| **Certificate** | Self-signed (X.509) |
| **Cipher Suites** | ECDHE+AESGCM, ECDHE+CHACHA20 |
| **Perfect Forward Secrecy** | Ephemeral key exchange (ECDHE/DHE) |

---

## Installation

### Prerequisites

```bash
# Python 3.8 or higher required
python3 --version
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
- `pycryptodome`: Cryptographic operations (RSA, AES, PBKDF2)
- `cryptography`: SSL/TLS certificate generation
- `prompt_toolkit`: Enhanced terminal UI

### Generate SSL Certificates

```bash
python3 generate_certificates.py
```

This creates self-signed certificates in `~/.secure_messenger/certs/`:
- `server.crt`: Server certificate (valid for 365 days)
- `server.key`: Server private key

---

## Usage

### Start the Server

```bash
python3 server.py
```

**Optional arguments:**
- `--host <address>`: Bind address (default: 0.0.0.0)
- `--port <port>`: Listen port (default: 1315)

### Start a Client

```bash
python3 client.py
```

**Optional arguments:**
- `--host <address>`: Server address (default: localhost)
- `--port <port>`: Server port (default: 1315)

### First-Time Setup

1. **Create Account**: Choose option 1 to register
2. **Set Password**: Minimum 6 characters
3. **Keys Generated**: RSA keypair created and stored locally
4. **Login**: Use same credentials to authenticate

### Messaging Modes

**Broadcast Mode (Default):**
- Messages sent to all online users
- Public conversation

**Private Room Mode:**
```bash
/room <username>  # Enter private room with user
/leave            # Return to broadcast mode
```

**Single Private Message:**
```bash
/msg <username> <message>  # One-time private message
```

### Available Commands

| Command | Description |
|---------|-------------|
| `/room <user>` | Enter private room with user |
| `/leave` | Leave private room |
| `/msg <user> <text>` | Send single private message |
| `/users` | List online users |
| `/history [count]` | View message history (default: 20) |
| `/clear` | Clear screen |
| `/help` | Show help |
| `/exit` | Exit application |

### Mention System

Users can be mentioned in messages using `@username`:
- Mentions highlighted in sender's and recipient's view
- Visual notification when you're mentioned

---

## File Structure

```
pyMessenger/
├── client.py                 # Client application
├── server.py                 # Server application
├── user_store.py            # User database and authentication
├── generate_certificates.py  # SSL certificate generator
├── requirements.txt         # Python dependencies
└── README.md               # This file

ON LINUX/UNOX:
User Data:
~/.secure_messenger_client/
└── keys/
    └── {username}_private.key  # Encrypted private key
ON WINDOWS:
User Data:
C:\Users\[YOUR_USER]\.secure_messenger_client\
└── keys/
    └── {username}_private.key  # Encrypted private key

~/.secure_messenger/
├── certs/
│   ├── server.crt           # Server certificate
│   └── server.key           # Server private key
├── logs/
│   └── security.log         # Security audit log
├── keys/
│   └── (server-stored keys) # Public keys only
└── users.json              # User database
```

---

## Security Considerations

### Threat Model

**Protected Against:**
- Passive network eavesdropping (TLS + E2EE)
- Message tampering (authenticated encryption)
- Server compromise (E2EE, server never sees plaintext)
- Brute force attacks (rate limiting, PBKDF2)
- Timing attacks (constant-time comparisons)
- Replay attacks (nonce-based challenges)

---

## Technical Specifications

### Cryptographic Algorithms

| Component | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Asymmetric | RSA-OAEP | 2048-bit | Key exchange |
| Symmetric | AES-EAX | 256-bit | Message encryption |
| Hash | SHA-256 | 256-bit | All hashing operations |
| KDF | PBKDF2-SHA256 | 256-bit output | 100,000 iterations |
| MAC | HMAC-SHA256 | 256-bit | Challenge-response |

### Protocol Details

**Message Format:**
```json
{
  "type": "encrypted_send",
  "from": "sender_username",
  "targets": ["recipient1", "recipient2"],
  "ciphertext": "<base64-encoded>",
  "nonce": "<base64-encoded>",
  "tag": "<base64-encoded>",
  "keys": {
    "recipient1": "<base64-encoded-encrypted-key>",
    "recipient2": "<base64-encoded-encrypted-key>"
  }
}
```

**All binary data is Base64-encoded for JSON transport.**

---

## License

MIT Licence

---

## Authors

MohamedG. - M. M. Sabaly
