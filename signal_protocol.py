"""Signal-inspired cryptographic primitives for pyMessenger.

This module implements a compact Signal-like design:
- long-term identity signing key (Ed25519)
- long-term identity DH key (X25519)
- signed prekey (X25519)
- one-time prekeys (X25519)
- X3DH-style session establishment
- symmetric message ratchet with AES-GCM
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PRIVATE_BUNDLE_AAD = b"pyMessenger-signal-private-bundle-v1"
SIGNED_PREKEY_AAD = b"pyMessenger-signal-signed-prekey-v1"
SESSION_INFO = b"pyMessenger-signal-session-v1"
ROOT_KEY_INFO = b"pyMessenger-signal-root-v1"
RATCHET_INFO = b"pyMessenger-signal-ratchet-v1"
CHAIN_INFO_SEND = b"pyMessenger-signal-chain-send-v1"
CHAIN_INFO_RECV = b"pyMessenger-signal-chain-recv-v1"
MESSAGE_INFO = b"pyMessenger-signal-message-v1"
MAX_SKIPPED_MESSAGE_KEYS = 2000


def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode_text(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return base64.b64decode(value)


def _raw_public_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _raw_private_bytes(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_x25519_public(value: bytes):
    return x25519.X25519PublicKey.from_public_bytes(value)


def _load_ed25519_public(value: bytes):
    return ed25519.Ed25519PublicKey.from_public_bytes(value)


def _hkdf(data: bytes, *, length: int, info: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(data)


def _derive_chain_step(chain_key: bytes) -> tuple[bytes, bytes]:
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return next_chain_key, message_key


def _derive_root_and_chain(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    derived = _hkdf(dh_output, length=64, info=RATCHET_INFO, salt=root_key)
    return derived[:32], derived[32:]


def _bundle_fingerprint(identity_sign_public: bytes, identity_dh_public: bytes) -> str:
    digest = hashlib.sha256(identity_sign_public + identity_dh_public).digest()
    return digest.hex()


@dataclass
class SignalKeyMaterial:
    """Local Signal-style key material for a single user."""

    username: str
    identity_sign_private: ed25519.Ed25519PrivateKey
    identity_dh_private: x25519.X25519PrivateKey
    signed_prekey_private: x25519.X25519PrivateKey
    signed_prekey_id: int
    signed_prekey_signature: bytes
    one_time_prekeys_private: dict[int, x25519.X25519PrivateKey] = field(default_factory=dict)
    next_prekey_id: int = 1

    @classmethod
    def generate(cls, username: str, one_time_prekey_count: int = 50) -> "SignalKeyMaterial":
        identity_sign_private = ed25519.Ed25519PrivateKey.generate()
        identity_dh_private = x25519.X25519PrivateKey.generate()
        signed_prekey_private = x25519.X25519PrivateKey.generate()
        signed_prekey_id = secrets.randbits(31)
        signed_prekey_public = _raw_public_bytes(signed_prekey_private.public_key())
        signed_prekey_signature = identity_sign_private.sign(SIGNED_PREKEY_AAD + signed_prekey_public)

        material = cls(
            username=username,
            identity_sign_private=identity_sign_private,
            identity_dh_private=identity_dh_private,
            signed_prekey_private=signed_prekey_private,
            signed_prekey_id=signed_prekey_id,
            signed_prekey_signature=signed_prekey_signature,
            one_time_prekeys_private={},
            next_prekey_id=1,
        )
        material.ensure_one_time_prekeys(one_time_prekey_count)
        return material

    @classmethod
    def from_private_record(cls, record: dict[str, Any]) -> "SignalKeyMaterial":
        identity_sign_private = ed25519.Ed25519PrivateKey.from_private_bytes(
            b64decode_text(record["identity_sign_private"])
        )
        identity_dh_private = x25519.X25519PrivateKey.from_private_bytes(
            b64decode_text(record["identity_dh_private"])
        )
        signed_prekey_private = x25519.X25519PrivateKey.from_private_bytes(
            b64decode_text(record["signed_prekey_private"])
        )
        one_time_prekeys = {
            int(item["id"]): x25519.X25519PrivateKey.from_private_bytes(
                b64decode_text(item["private"])
            )
            for item in record.get("one_time_prekeys", [])
        }
        return cls(
            username=record["username"],
            identity_sign_private=identity_sign_private,
            identity_dh_private=identity_dh_private,
            signed_prekey_private=signed_prekey_private,
            signed_prekey_id=int(record["signed_prekey_id"]),
            signed_prekey_signature=b64decode_text(record["signed_prekey_signature"]),
            one_time_prekeys_private=one_time_prekeys,
            next_prekey_id=int(record.get("next_prekey_id", len(one_time_prekeys) + 1)),
        )

    def to_private_record(self) -> dict[str, Any]:
        return {
            "version": 1,
            "username": self.username,
            "identity_sign_private": b64encode_bytes(_raw_private_bytes(self.identity_sign_private)),
            "identity_dh_private": b64encode_bytes(_raw_private_bytes(self.identity_dh_private)),
            "signed_prekey_id": self.signed_prekey_id,
            "signed_prekey_private": b64encode_bytes(_raw_private_bytes(self.signed_prekey_private)),
            "signed_prekey_signature": b64encode_bytes(self.signed_prekey_signature),
            "one_time_prekeys": [
                {
                    "id": key_id,
                    "private": b64encode_bytes(_raw_private_bytes(private_key)),
                }
                for key_id, private_key in sorted(self.one_time_prekeys_private.items())
            ],
            "next_prekey_id": self.next_prekey_id,
        }

    def ensure_one_time_prekeys(self, minimum_count: int = 50) -> None:
        while len(self.one_time_prekeys_private) < minimum_count:
            key_id = self.next_prekey_id
            self.one_time_prekeys_private[key_id] = x25519.X25519PrivateKey.generate()
            self.next_prekey_id += 1

    def rotate_prekey_bundle(self, one_time_prekey_count: int = 50) -> None:
        """Rotate the signed prekey and replace the one-time prekey pool.

        The long-term identity keys stay stable, while the medium-term and one-time
        prekeys are refreshed on each login.
        """
        self.signed_prekey_private = x25519.X25519PrivateKey.generate()
        self.signed_prekey_id = secrets.randbits(31)
        signed_prekey_public = _raw_public_bytes(self.signed_prekey_private.public_key())
        self.signed_prekey_signature = self.identity_sign_private.sign(
            SIGNED_PREKEY_AAD + signed_prekey_public
        )
        self.one_time_prekeys_private = {}
        self.next_prekey_id = 1
        self.ensure_one_time_prekeys(one_time_prekey_count)

    def to_public_bundle(self) -> dict[str, Any]:
        identity_sign_public = _raw_public_bytes(self.identity_sign_private.public_key())
        identity_dh_public = _raw_public_bytes(self.identity_dh_private.public_key())
        signed_prekey_public = _raw_public_bytes(self.signed_prekey_private.public_key())
        return {
            "version": 1,
            "username": self.username,
            "identity_sign_pub": b64encode_bytes(identity_sign_public),
            "identity_dh_pub": b64encode_bytes(identity_dh_public),
            "signed_prekey_id": self.signed_prekey_id,
            "signed_prekey_pub": b64encode_bytes(signed_prekey_public),
            "signed_prekey_signature": b64encode_bytes(self.signed_prekey_signature),
            "one_time_prekeys": [
                {
                    "id": key_id,
                    "public": b64encode_bytes(_raw_public_bytes(private_key.public_key())),
                }
                for key_id, private_key in sorted(self.one_time_prekeys_private.items())
            ],
            "identity_fingerprint": self.identity_fingerprint(),
        }

    def identity_fingerprint(self) -> str:
        return _bundle_fingerprint(
            _raw_public_bytes(self.identity_sign_private.public_key()),
            _raw_public_bytes(self.identity_dh_private.public_key()),
        )


@dataclass
class SignalPeerBundle:
    """Public bundle fetched from the server for a remote peer."""

    username: str
    identity_sign_pub: bytes
    identity_dh_pub: bytes
    signed_prekey_id: int
    signed_prekey_pub: bytes
    signed_prekey_signature: bytes
    one_time_prekey_id: int | None = None
    one_time_prekey_pub: bytes | None = None
    identity_fingerprint: str = ""
    version: int = 1

    @classmethod
    def from_dict(cls, username: str, bundle: dict[str, Any]) -> "SignalPeerBundle":
        one_time_prekeys = bundle.get("one_time_prekeys") or []
        one_time_prekey_id = None
        one_time_prekey_pub = None
        if one_time_prekeys:
            first_prekey = one_time_prekeys[0]
            one_time_prekey_id = int(first_prekey["id"])
            one_time_prekey_pub = b64decode_text(first_prekey["public"])

        return cls(
            username=username,
            identity_sign_pub=b64decode_text(bundle["identity_sign_pub"]),
            identity_dh_pub=b64decode_text(bundle["identity_dh_pub"]),
            signed_prekey_id=int(bundle["signed_prekey_id"]),
            signed_prekey_pub=b64decode_text(bundle["signed_prekey_pub"]),
            signed_prekey_signature=b64decode_text(bundle["signed_prekey_signature"]),
            one_time_prekey_id=one_time_prekey_id,
            one_time_prekey_pub=one_time_prekey_pub,
            identity_fingerprint=str(bundle.get("identity_fingerprint", "")),
            version=int(bundle.get("version", 1)),
        )

    def verify(self) -> None:
        public_key = _load_ed25519_public(self.identity_sign_pub)
        public_key.verify(self.signed_prekey_signature, SIGNED_PREKEY_AAD + self.signed_prekey_pub)

    def bundle_fingerprint(self) -> str:
        return _bundle_fingerprint(self.identity_sign_pub, self.identity_dh_pub)


@dataclass
class SignalSession:
    """Per-peer symmetric session state."""

    peer_username: str
    session_id: str
    root_key: bytes
    our_ratchet_private: x25519.X25519PrivateKey
    their_ratchet_public: bytes | None
    send_chain_key: bytes
    recv_chain_key: bytes
    send_counter: int = 0
    recv_counter: int = 0
    pending_send_dh_ratchet: bool = False
    skipped_message_keys: dict[tuple[bytes, int], bytes] = field(default_factory=dict)
    historical_ratchet_pubs: list[bytes] = field(default_factory=list)

    @classmethod
    def from_seed(
        cls,
        peer_username: str,
        seed: bytes,
        session_id: str,
        initiator: bool,
        our_ratchet_private: x25519.X25519PrivateKey,
        their_ratchet_public: bytes | None = None,
        pending_send_dh_ratchet: bool = False,
    ) -> "SignalSession":
        root_key = _hkdf(seed, length=32, info=ROOT_KEY_INFO, salt=None)
        send_key = _hkdf(root_key, length=32, info=CHAIN_INFO_SEND, salt=None)
        recv_key = _hkdf(root_key, length=32, info=CHAIN_INFO_RECV, salt=None)
        if not initiator:
            send_key, recv_key = recv_key, send_key
        return cls(
            peer_username=peer_username,
            session_id=session_id,
            root_key=root_key,
            our_ratchet_private=our_ratchet_private,
            their_ratchet_public=their_ratchet_public,
            send_chain_key=send_key,
            recv_chain_key=recv_key,
            pending_send_dh_ratchet=pending_send_dh_ratchet,
        )

    @property
    def our_ratchet_public(self) -> bytes:
        return _raw_public_bytes(self.our_ratchet_private.public_key())

    def _current_ratchet_public(self) -> bytes | None:
        return self.their_ratchet_public

    def _store_skipped_message_key(self, ratchet_pub: bytes, counter: int, message_key: bytes) -> None:
        key_id = (ratchet_pub, counter)
        if key_id in self.skipped_message_keys:
            return

        if len(self.skipped_message_keys) >= MAX_SKIPPED_MESSAGE_KEYS:
            oldest_key_id = next(iter(self.skipped_message_keys))
            self.skipped_message_keys.pop(oldest_key_id, None)

        self.skipped_message_keys[key_id] = message_key

    def _pop_skipped_message_key(self, ratchet_pub: bytes, counter: int) -> bytes | None:
        return self.skipped_message_keys.pop((ratchet_pub, counter), None)

    def _cache_skipped_message_keys(self, ratchet_pub: bytes, until_counter: int) -> None:
        while self.recv_counter + 1 < until_counter:
            self.recv_chain_key, skipped_key = _derive_chain_step(self.recv_chain_key)
            self.recv_counter += 1
            self._store_skipped_message_key(ratchet_pub, self.recv_counter, skipped_key)

    def _advance_send_dh_ratchet(self) -> None:
        if self.their_ratchet_public is None:
            raise ValueError("Cannot advance send ratchet before receiving a peer ratchet public key")

        new_local_private = x25519.X25519PrivateKey.generate()
        dh_output = new_local_private.exchange(_load_x25519_public(self.their_ratchet_public))
        self.root_key, self.send_chain_key = _derive_root_and_chain(self.root_key, dh_output)
        self.our_ratchet_private = new_local_private
        self.send_counter = 0
        self.pending_send_dh_ratchet = False

    def _advance_receive_dh_ratchet(self, new_remote_public: bytes) -> None:
        if self.their_ratchet_public is not None:
            if self.their_ratchet_public not in self.historical_ratchet_pubs:
                self.historical_ratchet_pubs.append(self.their_ratchet_public)
                if len(self.historical_ratchet_pubs) > 8:
                    self.historical_ratchet_pubs.pop(0)

        dh_output = self.our_ratchet_private.exchange(_load_x25519_public(new_remote_public))
        self.root_key, self.recv_chain_key = _derive_root_and_chain(self.root_key, dh_output)
        self.their_ratchet_public = new_remote_public
        self.recv_counter = 0
        self.pending_send_dh_ratchet = True

    def _aad(self, sender: str, recipient: str, counter: int, is_private: bool, ratchet_pub: bytes | None = None) -> bytes:
        return json.dumps(
            {
                "session_id": self.session_id,
                "sender": sender,
                "recipient": recipient,
                "counter": counter,
                "is_private": is_private,
                "ratchet_pub": b64encode_bytes(ratchet_pub) if ratchet_pub is not None else None,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def encrypt_message(self, plaintext: bytes, sender: str, recipient: str, is_private: bool) -> dict[str, Any]:
        if self.pending_send_dh_ratchet:
            self._advance_send_dh_ratchet()

        ratchet_pub = self.our_ratchet_public
        self.send_counter += 1
        self.send_chain_key, message_key = _derive_chain_step(self.send_chain_key)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(message_key).encrypt(
            nonce,
            plaintext,
            self._aad(sender, recipient, self.send_counter, is_private, ratchet_pub),
        )
        return {
            "nonce": b64encode_bytes(nonce),
            "ciphertext": b64encode_bytes(ciphertext),
            "counter": self.send_counter,
            "ratchet_pub": b64encode_bytes(ratchet_pub),
        }

    def decrypt_message(self, packet: dict[str, Any], sender: str, recipient: str) -> bytes:
        counter = int(packet["counter"])
        ratchet_pub_b64 = packet.get("ratchet_pub")
        ratchet_pub = b64decode_text(ratchet_pub_b64) if ratchet_pub_b64 else self.their_ratchet_public
        if ratchet_pub is None:
            raise ValueError("Missing Signal ratchet public key")

        skipped_message_key = self._pop_skipped_message_key(ratchet_pub, counter)
        if skipped_message_key is not None:
            nonce = b64decode_text(packet["nonce"])
            ciphertext = b64decode_text(packet["ciphertext"])
            return AESGCM(skipped_message_key).decrypt(
                nonce,
                ciphertext,
                self._aad(sender, recipient, counter, bool(packet.get("is_private", False)), ratchet_pub),
            )

        if self.their_ratchet_public is None:
            self.their_ratchet_public = ratchet_pub
        elif ratchet_pub != self.their_ratchet_public:
            if ratchet_pub in self.historical_ratchet_pubs:
                raise ValueError("Stale Signal ratchet public key")
            self._advance_receive_dh_ratchet(ratchet_pub)

        if counter <= self.recv_counter:
            skipped_message_key = self._pop_skipped_message_key(self.their_ratchet_public, counter)
            if skipped_message_key is None:
                raise ValueError("Out-of-order or replayed Signal message")

            nonce = b64decode_text(packet["nonce"])
            ciphertext = b64decode_text(packet["ciphertext"])
            return AESGCM(skipped_message_key).decrypt(
                nonce,
                ciphertext,
                self._aad(sender, recipient, counter, bool(packet.get("is_private", False)), self.their_ratchet_public),
            )

        if counter > self.recv_counter + 1:
            self._cache_skipped_message_keys(self.their_ratchet_public, counter)

        self.recv_chain_key, message_key = _derive_chain_step(self.recv_chain_key)
        nonce = b64decode_text(packet["nonce"])
        ciphertext = b64decode_text(packet["ciphertext"])
        plaintext = AESGCM(message_key).decrypt(
            nonce,
            ciphertext,
            self._aad(sender, recipient, counter, bool(packet.get("is_private", False)), self.their_ratchet_public),
        )
        self.recv_counter = counter
        return plaintext


class SignalKeyStore:
    """Encrypted local storage for Signal key material."""

    def __init__(self, base_dir: Path | None = None):
        self.config_dir = base_dir or (Path.home() / ".secure_messenger_client")
        self.signal_dir = self.config_dir / "signal"
        self.signal_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.signal_dir, 0o700)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,
        )
        return kdf.derive(password.encode("utf-8"))

    def _key_file(self, username: str) -> Path:
        return self.signal_dir / f"{username}_signal.key"

    def exists(self, username: str) -> bool:
        return self._key_file(username).exists()

    def save(self, username: str, material: SignalKeyMaterial, password: str) -> None:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = json.dumps(material.to_private_record()).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, PRIVATE_BUNDLE_AAD)
        key_file = self._key_file(username)
        with open(key_file, "wb") as f:
            f.write(salt + nonce + ciphertext)
        if os.name != "nt":
            os.chmod(key_file, 0o600)

    def load(self, username: str, password: str) -> SignalKeyMaterial | None:
        key_file = self._key_file(username)
        if not key_file.exists():
            return None
        try:
            with open(key_file, "rb") as f:
                data = f.read()
            salt = data[:16]
            nonce = data[16:28]
            ciphertext = data[28:]
            key = self._derive_key(password, salt)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, PRIVATE_BUNDLE_AAD)
            record = json.loads(plaintext.decode("utf-8"))
            return SignalKeyMaterial.from_private_record(record)
        except Exception:
            return None


def create_x3dh_seed(local_material: SignalKeyMaterial, peer_bundle: SignalPeerBundle) -> tuple[bytes, dict[str, Any]]:
    """Compute the X3DH-style shared secret seed and handshake transcript."""
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = _raw_public_bytes(ephemeral_private.public_key())

    dh_parts = [
        local_material.identity_dh_private.exchange(_load_x25519_public(peer_bundle.signed_prekey_pub)),
        ephemeral_private.exchange(_load_x25519_public(peer_bundle.identity_dh_pub)),
        ephemeral_private.exchange(_load_x25519_public(peer_bundle.signed_prekey_pub)),
    ]

    if peer_bundle.one_time_prekey_pub is not None:
        dh_parts.append(ephemeral_private.exchange(_load_x25519_public(peer_bundle.one_time_prekey_pub)))

    shared_material = b"".join(dh_parts)
    seed = _hkdf(shared_material, length=64, info=SESSION_INFO, salt=b"\x00" * 32)

    session_id = hashlib.sha256(
        seed + local_material.username.encode("utf-8") + peer_bundle.username.encode("utf-8")
    ).hexdigest()[:32]

    transcript = json.dumps(
        {
            "protocol": "pyMessenger-signal-init-v1",
            "session_id": session_id,
            "sender": local_material.username,
            "recipient": peer_bundle.username,
            "sender_identity_sign_pub": b64encode_bytes(_raw_public_bytes(local_material.identity_sign_private.public_key())),
            "sender_identity_dh_pub": b64encode_bytes(_raw_public_bytes(local_material.identity_dh_private.public_key())),
            "sender_ephemeral_pub": b64encode_bytes(ephemeral_public),
            "recipient_signed_prekey_id": peer_bundle.signed_prekey_id,
            "recipient_one_time_prekey_id": peer_bundle.one_time_prekey_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return seed, {
        "ephemeral_private": ephemeral_private,
        "ephemeral_public": ephemeral_public,
        "session_id": session_id,
        "transcript": transcript,
    }


def create_initiator_session(
    local_material: SignalKeyMaterial,
    peer_bundle: SignalPeerBundle,
    plaintext: bytes,
    sender_username: str,
    recipient_username: str,
    is_private: bool,
) -> tuple[SignalSession, dict[str, Any]]:
    seed, handshake = create_x3dh_seed(local_material, peer_bundle)
    session = SignalSession.from_seed(
        peer_username=recipient_username,
        seed=seed,
        session_id=handshake["session_id"],
        initiator=True,
        our_ratchet_private=handshake["ephemeral_private"],
        their_ratchet_public=peer_bundle.one_time_prekey_pub or peer_bundle.signed_prekey_pub,
    )

    encrypted = session.encrypt_message(plaintext, sender_username, recipient_username, is_private)
    signature = local_material.identity_sign_private.sign(handshake["transcript"])

    packet = {
        "type": "signal_session_init",
        "from": sender_username,
        "to": recipient_username,
        "session_id": session.session_id,
        "counter": encrypted["counter"],
        "is_private": is_private,
        "ratchet_pub": encrypted["ratchet_pub"],
        "sender_identity_sign_pub": b64encode_bytes(_raw_public_bytes(local_material.identity_sign_private.public_key())),
        "sender_identity_dh_pub": b64encode_bytes(_raw_public_bytes(local_material.identity_dh_private.public_key())),
        "sender_ephemeral_pub": b64encode_bytes(handshake["ephemeral_public"]),
        "recipient_signed_prekey_id": peer_bundle.signed_prekey_id,
        "recipient_one_time_prekey_id": peer_bundle.one_time_prekey_id,
        "signature": b64encode_bytes(signature),
        "nonce": encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"],
    }
    return session, packet


def accept_session_init(
    local_material: SignalKeyMaterial,
    packet: dict[str, Any],
) -> tuple[SignalSession, bytes]:
    sender_username = packet["from"]
    recipient_username = packet["to"]
    session_id = packet["session_id"]
    sender_identity_sign_pub = b64decode_text(packet["sender_identity_sign_pub"])
    sender_identity_dh_pub = b64decode_text(packet["sender_identity_dh_pub"])
    sender_ephemeral_pub = b64decode_text(packet["sender_ephemeral_pub"])
    signature = b64decode_text(packet["signature"])

    transcript = json.dumps(
        {
            "protocol": "pyMessenger-signal-init-v1",
            "session_id": session_id,
            "sender": sender_username,
            "recipient": recipient_username,
            "sender_identity_sign_pub": packet["sender_identity_sign_pub"],
            "sender_identity_dh_pub": packet["sender_identity_dh_pub"],
            "sender_ephemeral_pub": packet["sender_ephemeral_pub"],
            "recipient_signed_prekey_id": packet.get("recipient_signed_prekey_id"),
            "recipient_one_time_prekey_id": packet.get("recipient_one_time_prekey_id"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    sender_sign_public = _load_ed25519_public(sender_identity_sign_pub)
    sender_sign_public.verify(signature, transcript)

    dh_parts = [
        local_material.signed_prekey_private.exchange(_load_x25519_public(sender_identity_dh_pub)),
        local_material.identity_dh_private.exchange(_load_x25519_public(sender_ephemeral_pub)),
        local_material.signed_prekey_private.exchange(_load_x25519_public(sender_ephemeral_pub)),
    ]

    one_time_prekey_id = packet.get("recipient_one_time_prekey_id")
    one_time_prekey_private = local_material.one_time_prekeys_private.pop(int(one_time_prekey_id), None) if one_time_prekey_id is not None else None
    if one_time_prekey_private is not None:
        dh_parts.append(one_time_prekey_private.exchange(_load_x25519_public(sender_ephemeral_pub)))

    shared_material = b"".join(dh_parts)
    seed = _hkdf(shared_material, length=64, info=SESSION_INFO, salt=b"\x00" * 32)
    session = SignalSession.from_seed(
        peer_username=sender_username,
        seed=seed,
        session_id=session_id,
        initiator=False,
        our_ratchet_private=local_material.signed_prekey_private,
        their_ratchet_public=sender_ephemeral_pub,
        pending_send_dh_ratchet=True,
    )
    plaintext = session.decrypt_message(packet, sender_username, recipient_username)
    return session, plaintext


def encrypt_session_message(
    session: SignalSession,
    plaintext: bytes,
    sender_username: str,
    recipient_username: str,
    is_private: bool,
) -> dict[str, Any]:
    packet = session.encrypt_message(plaintext, sender_username, recipient_username, is_private)
    packet.update(
        {
            "type": "signal_message",
            "from": sender_username,
            "to": recipient_username,
            "session_id": session.session_id,
            "is_private": is_private,
        }
    )
    return packet


def decrypt_session_message(
    session: SignalSession,
    packet: dict[str, Any],
    sender_username: str,
    recipient_username: str,
) -> bytes:
    return session.decrypt_message(packet, sender_username, recipient_username)
