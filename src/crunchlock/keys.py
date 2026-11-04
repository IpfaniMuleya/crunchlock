"""File keys, key slots, and X25519 identities (public-key sharing)."""
from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import kdf
from .errors import CorruptFileError, CrunchlockError, WrongKeyError
from .format import Header, PasswordSlot, X25519Slot

PUB_PREFIX = "clkpub1:"
KEYFILE_MAGIC = b"CLKK"
_KEYFILE = struct.Struct(">4sBIIB16s12s")
_SLOT_AAD = b"crunchlock-slot-v1"


def new_file_key() -> bytes:
    return os.urandom(32)


def _wrap(kek: bytes, file_key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(kek).encrypt(nonce, file_key, aad)


def _unwrap(kek: bytes, nonce: bytes, wrapped: bytes, aad: bytes) -> bytes | None:
    try:
        return AESGCM(kek).decrypt(nonce, wrapped, aad)
    except InvalidTag:
        return None


def _x25519_kek(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    if shared == bytes(32):
        raise CorruptFileError("invalid public key")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=b"crunchlock x25519 v1").derive(shared)


# --------------------------------------------------------------------------- slots

def make_password_slot(header_prefix: bytes, file_key: bytes, password: str | None,
                       keyfile: bytes | None, params: kdf.KdfParams) -> PasswordSlot:
    if not password and keyfile is None:
        raise CrunchlockError("a password or keyfile is required")
    slot = PasswordSlot(params, keyfile is not None, os.urandom(kdf.SALT_LEN))
    kek = kdf.derive(kdf.secret_bytes(password, keyfile), slot.salt, params)
    slot.nonce, slot.wrapped = _wrap(kek, file_key, _SLOT_AAD + header_prefix + slot.public_part())
    return slot


def make_x25519_slot(header_prefix: bytes, file_key: bytes, recipient: X25519PublicKey) -> X25519Slot:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    rpub = recipient.public_bytes_raw()
    kek = _x25519_kek(eph.exchange(recipient), eph_pub, rpub)
    slot = X25519Slot(eph_pub)
    slot.nonce, slot.wrapped = _wrap(kek, file_key, _SLOT_AAD + header_prefix + slot.public_part())
    return slot


def open_file_key(header: Header, password: str | None = None, keyfile: bytes | None = None,
                  identity: X25519PrivateKey | None = None) -> bytes:
    """Try the supplied secrets against every key slot; return the file key."""
    prefix = header.prefix()
    tried = False
    if identity is not None:
        my_pub = identity.public_key().public_bytes_raw()
        for slot in header.slots:
            if isinstance(slot, X25519Slot):
                tried = True
                try:
                    shared = identity.exchange(X25519PublicKey.from_public_bytes(slot.ephemeral_pub))
                    kek = _x25519_kek(shared, slot.ephemeral_pub, my_pub)
                except (ValueError, CorruptFileError):
                    continue
                key = _unwrap(kek, slot.nonce, slot.wrapped, _SLOT_AAD + prefix + slot.public_part())
                if key is not None:
                    return key
    if password or keyfile is not None:
        secret = kdf.secret_bytes(password, keyfile)
        for slot in header.slots:
            if isinstance(slot, PasswordSlot):
                tried = True
                kek = kdf.derive(secret, slot.salt, slot.params)
                key = _unwrap(kek, slot.nonce, slot.wrapped, _SLOT_AAD + prefix + slot.public_part())
                if key is not None:
                    return key
    if not tried:
        kinds = describe_slots(header)
        raise WrongKeyError(f"this file can only be opened with: {kinds}")
    raise WrongKeyError("wrong password, keyfile or private key")


def describe_slots(header: Header) -> str:
    parts = []
    for s in header.slots:
        if isinstance(s, PasswordSlot):
            parts.append("password + keyfile" if s.uses_keyfile else "password")
        else:
            parts.append("private key")
    return ", ".join(sorted(set(parts)))


def needs_keyfile(header: Header) -> bool:
    return any(isinstance(s, PasswordSlot) and s.uses_keyfile for s in header.slots)


# ------------------------------------------------------------------ identities

@dataclass
class Identity:
    private: X25519PrivateKey

    @property
    def public(self) -> X25519PublicKey:
        return self.private.public_key()


def generate_identity() -> Identity:
    return Identity(X25519PrivateKey.generate())


def public_key_to_text(pub: X25519PublicKey) -> str:
    return PUB_PREFIX + base64.urlsafe_b64encode(pub.public_bytes_raw()).decode().rstrip("=")


def public_key_from_text(text: str) -> X25519PublicKey:
    text = text.strip()
    if not text.startswith(PUB_PREFIX):
        raise CrunchlockError("not a crunchlock public key (expected 'clkpub1:...')")
    body = text[len(PUB_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except ValueError as e:
        raise CrunchlockError("malformed public key") from e
    if len(raw) != 32:
        raise CrunchlockError("malformed public key")
    return X25519PublicKey.from_public_bytes(raw)


def fingerprint(pub: X25519PublicKey) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(pub.public_bytes_raw())
    d = h.finalize().hex()[:16]
    return ":".join(d[i:i + 4] for i in range(0, 16, 4))


def save_private_key(identity: Identity, passphrase: str,
                     params: kdf.KdfParams = kdf.PROFILES["standard"]) -> bytes:
    """Serialize a private key, encrypted with *passphrase* (Argon2id + AES-GCM)."""
    if not passphrase:
        raise CrunchlockError("a passphrase is required to protect the private key")
    salt, nonce = os.urandom(16), os.urandom(12)
    head = _KEYFILE.pack(KEYFILE_MAGIC, 1, params.time_cost, params.memory_kib,
                         params.parallelism, salt, nonce)
    kek = kdf.derive(kdf.secret_bytes(passphrase, None), salt, params)
    raw = identity.private.private_bytes(serialization.Encoding.Raw,
                                         serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption())
    return head + AESGCM(kek).encrypt(nonce, raw, head)


def load_private_key(data: bytes, passphrase: str) -> Identity:
    if len(data) != _KEYFILE.size + 48 or not data.startswith(KEYFILE_MAGIC):
        raise CrunchlockError("not a crunchlock private key file")
    head = data[:_KEYFILE.size]
    _, ver, t, m, p, salt, nonce = _KEYFILE.unpack(head)
    if ver != 1:
        raise CrunchlockError("unsupported private key version")
    kek = kdf.derive(kdf.secret_bytes(passphrase, None), salt, kdf.KdfParams(t, m, p))
    try:
        raw = AESGCM(kek).decrypt(nonce, data[_KEYFILE.size:], head)
    except InvalidTag:
        raise WrongKeyError("wrong passphrase for private key") from None
    return Identity(X25519PrivateKey.from_private_bytes(raw))
