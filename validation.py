import base64
import re
from pathlib import Path
from typing import Any


class ValidationError(Exception):
    pass


def validate_username(username: str) -> str:
    if not username or not isinstance(username, str):
        raise ValidationError("Invalid username")

    username = username.strip()
    if len(username) < 3 or len(username) > 32:
        raise ValidationError("Username must be 3-32 characters")

    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise ValidationError("Username can only contain letters, numbers, underscores, and hyphens")

    return username


def validate_password(password: str) -> str:
    if not password or not isinstance(password, str):
        raise ValidationError("Invalid password")

    if len(password) < 6:
        raise ValidationError("Password must be at least 6 characters")

    if len(password) > 128:
        raise ValidationError("Password too long")

    return password


def validate_message(message: str) -> str:
    if not isinstance(message, str):
        raise ValidationError("Invalid message type")

    if len(message) > 10000:
        raise ValidationError("Message too large")

    return message.strip()


def validate_file_path(file_path: str) -> Path:
    path = Path(file_path).resolve()

    if str(path).startswith('..'):
        raise ValidationError("Invalid file path")

    if not path.exists() or not path.is_file():
        raise ValidationError("File not found")

    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValidationError("File too large")

    return path


def validate_pubkey(pubkey_b64: str) -> str:
    if not pubkey_b64 or not isinstance(pubkey_b64, str):
        raise ValidationError("Invalid public key")

    try:
        pubkey_bytes = base64.b64decode(pubkey_b64)
        if len(pubkey_bytes) < 32 or len(pubkey_bytes) > 4096:
            raise ValidationError("Invalid public key size")
    except Exception:
        raise ValidationError("Invalid public key encoding")

    return pubkey_b64


def validate_nonce(nonce_b64: str) -> bytes:
    if not nonce_b64 or not isinstance(nonce_b64, str):
        raise ValidationError("Invalid nonce")

    try:
        nonce = base64.b64decode(nonce_b64)
        if len(nonce) != 12:
            raise ValidationError("Invalid nonce length")
    except Exception:
        raise ValidationError("Invalid nonce encoding")

    return nonce


def validate_ciphertext(ciphertext_b64: str) -> bytes:
    if not ciphertext_b64 or not isinstance(ciphertext_b64, str):
        raise ValidationError("Invalid ciphertext")

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        if len(ciphertext) > 10 * 1024 * 1024:
            raise ValidationError("Ciphertext too large")
    except Exception:
        raise ValidationError("Invalid ciphertext encoding")

    return ciphertext


def validate_crypto_packet(packet: dict) -> dict:
    if not isinstance(packet, dict):
        raise ValidationError("Invalid packet type")

    required_fields = ['type', 'nonce', 'ciphertext']

    for field in required_fields:
        if field not in packet:
            raise ValidationError(f"Missing required field: {field}")

    validate_nonce(packet['nonce'])
    validate_ciphertext(packet['ciphertext'])

    return packet


def validate_auth_request(auth_msg: dict) -> dict:
    if not isinstance(auth_msg, dict):
        raise ValidationError("Invalid auth request type")

    if auth_msg.get('type') != 'auth_request':
        raise ValidationError("Invalid auth request type")

    auth_type = auth_msg.get('auth_type')
    if auth_type not in ['register', 'login']:
        raise ValidationError("Invalid authentication type")

    return auth_msg


def validate_session_token(token: str) -> str:
    if not token or not isinstance(token, str):
        raise ValidationError("Invalid session token")

    if len(token) < 16 or len(token) > 128:
        raise ValidationError("Invalid session token length")

    return token


def validate_challenge_response(response: str) -> str:
    if not response or not isinstance(response, str):
        raise ValidationError("Invalid challenge response")

    try:
        decoded = base64.b64decode(response)
        if len(decoded) != 32:
            raise ValidationError("Invalid challenge response length")
    except Exception:
        raise ValidationError("Invalid challenge response encoding")

    return response


def validate_bundle(bundle: dict) -> dict:
    if not isinstance(bundle, dict):
        raise ValidationError("Invalid bundle type")

    required_fields = ['username', 'identity_sign_pub', 'identity_dh_pub',
                      'signed_prekey_id', 'signed_prekey_pub', 'signed_prekey_signature']

    for field in required_fields:
        if field not in bundle:
            raise ValidationError(f"Missing required bundle field: {field}")

    validate_username(bundle['username'])
    validate_pubkey(bundle['identity_sign_pub'])
    validate_pubkey(bundle['identity_dh_pub'])
    validate_pubkey(bundle['signed_prekey_pub'])
    validate_pubkey(bundle['signed_prekey_signature'])

    return bundle


def validate_file_size(size: int) -> int:
    if not isinstance(size, int) or size < 0:
        raise ValidationError("Invalid file size")

    if size > 100 * 1024 * 1024:
        raise ValidationError("File size exceeds maximum")

    return size


def validate_chunk_size(size: int) -> int:
    if not isinstance(size, int) or size < 0:
        raise ValidationError("Invalid chunk size")

    if size > 64 * 1024:
        raise ValidationError("Chunk size exceeds maximum")

    return size


def validate_counter(counter: int) -> int:
    if not isinstance(counter, int) or counter < 0:
        raise ValidationError("Invalid counter")

    if counter > 1000000:
        raise ValidationError("Counter too large")

    return counter


def validate_session_id(session_id: str) -> str:
    if not session_id or not isinstance(session_id, str):
        raise ValidationError("Invalid session ID")

    if len(session_id) < 16 or len(session_id) > 128:
        raise ValidationError("Invalid session ID length")

    return session_id


def validate_target_user(target: str) -> str:
    if not target or not isinstance(target, str):
        raise ValidationError("Invalid target user")

    return validate_username(target)


def validate_file_id(file_id: str) -> str:
    if not file_id or not isinstance(file_id, str):
        raise ValidationError("Invalid file ID")

    if len(file_id) < 8 or len(file_id) > 64:
        raise ValidationError("Invalid file ID length")

    return file_id


def validate_invite_id(invite_id: str) -> str:
    if not invite_id or not isinstance(invite_id, str):
        raise ValidationError("Invalid invite ID")

    if len(invite_id) < 8 or len(invite_id) > 64:
        raise ValidationError("Invalid invite ID length")

    return invite_id


def validate_request_id(request_id: str) -> str:
    if not request_id or not isinstance(request_id, str):
        raise ValidationError("Invalid request ID")

    if len(request_id) < 8 or len(request_id) > 64:
        raise ValidationError("Invalid request ID length")

    return request_id


def validate_signature(signature_b64: str) -> bytes:
    if not signature_b64 or not isinstance(signature_b64, str):
        raise ValidationError("Invalid signature")

    try:
        signature = base64.b64decode(signature_b64)
        if len(signature) < 32 or len(signature) > 128:
            raise ValidationError("Invalid signature length")
    except Exception:
        raise ValidationError("Invalid signature encoding")

    return signature


def validate_ratchet_pub(ratchet_pub_b64: str) -> bytes:
    if not ratchet_pub_b64 or not isinstance(ratchet_pub_b64, str):
        raise ValidationError("Invalid ratchet public key")

    try:
        ratchet_pub = base64.b64decode(ratchet_pub_b64)
        if len(ratchet_pub) != 32:
            raise ValidationError("Invalid ratchet public key length")
    except Exception:
        raise ValidationError("Invalid ratchet public key encoding")

    return ratchet_pub


def validate_encrypted_key(encrypted_key_b64: str) -> bytes:
    if not encrypted_key_b64 or not isinstance(encrypted_key_b64, str):
        raise ValidationError("Invalid encrypted key")

    try:
        encrypted_key = base64.b64decode(encrypted_key_b64)
        if len(encrypted_key) < 32 or len(encrypted_key) > 512:
            raise ValidationError("Invalid encrypted key length")
    except Exception:
        raise ValidationError("Invalid encrypted key encoding")

    return encrypted_key


def validate_tag(tag_b64: str) -> bytes:
    if not tag_b64 or not isinstance(tag_b64, str):
        raise ValidationError("Invalid tag")

    try:
        tag = base64.b64decode(tag_b64)
        if len(tag) != 16:
            raise ValidationError("Invalid tag length")
    except Exception:
        raise ValidationError("Invalid tag encoding")

    return tag


def validate_host(host: str) -> str:
    if not host or not isinstance(host, str):
        raise ValidationError("Invalid host")

    host = host.strip()
    if len(host) > 253:
        raise ValidationError("Host too long")

    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise ValidationError("Invalid host format")

    return host


def validate_port(port: int) -> int:
    if not isinstance(port, int):
        raise ValidationError("Invalid port type")

    if port < 1 or port > 65535:
        raise ValidationError("Port out of range")

    return port


def validate_ip_address(ip: str) -> str:
    if not ip or not isinstance(ip, str):
        raise ValidationError("Invalid IP address")

    ip = ip.strip()

    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^[0-9a-fA-F:]+$'

    if not (re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip)):
        raise ValidationError("Invalid IP address format")

    return ip


def sanitize_filename(filename: str) -> str:
    if not filename or not isinstance(filename, str):
        raise ValidationError("Invalid filename")

    filename = filename.strip()

    if len(filename) > 255:
        raise ValidationError("Filename too long")

    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)

    if filename in ['.', '..', '', 'CON', 'PRN', 'AUX', 'NUL'] or \
       filename.startswith(('COM', 'LPT')) and len(filename) == 4:
        raise ValidationError("Invalid filename")

    return filename


def validate_message_type(msg_type: str) -> str:
    if not msg_type or not isinstance(msg_type, str):
        raise ValidationError("Invalid message type")

    valid_types = [
        'auth_request', 'auth_response', 'auth_challenge', 'auth_result',
        'pubkey_announce', 'room_invite', 'room_invite_request',
        'room_invite_response', 'room_accepted', 'room_rejected',
        'signal_bundle_upload', 'signal_bundle_ack', 'signal_bundle_request',
        'signal_bundle_response', 'signal_send', 'signal_session_init',
        'signal_message', 'encrypted_send', 'encrypted_deliver',
        'file_offer', 'file_offer_failed', 'file_response', 'file_transfer',
        'error'
    ]

    if msg_type not in valid_types:
        raise ValidationError("Invalid message type")

    return msg_type


def validate_json_size(data: str, max_size: int = 1024 * 1024) -> str:
    if not isinstance(data, str):
        raise ValidationError("Invalid JSON data type")

    if len(data) > max_size:
        raise ValidationError("JSON data too large")

    return data


def validate_array_length(arr: list, max_length: int = 1000) -> list:
    if not isinstance(arr, list):
        raise ValidationError("Invalid array type")

    if len(arr) > max_length:
        raise ValidationError("Array too long")

    return arr


def validate_dict_size(d: dict, max_size: int = 1000) -> dict:
    if not isinstance(d, dict):
        raise ValidationError("Invalid dict type")

    if len(d) > max_size:
        raise ValidationError("Dictionary too large")

    return d


def validate_auth_request(auth_msg: dict) -> dict:
    if not isinstance(auth_msg, dict):
        raise ValidationError("Invalid auth request type")

    if auth_msg.get('type') != 'auth_request':
        raise ValidationError("Invalid auth request type")

    auth_type = auth_msg.get('auth_type')
    if auth_type not in ['register', 'login']:
        raise ValidationError("Invalid authentication type")

    return auth_msg