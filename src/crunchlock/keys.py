"""File keys, key slots, and X25519 identities (public-key sharing)."""
from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import kdf
from .errors import CorruptFileError, CrunchlockError, WrongKeyError
from .format import Header, PasswordSlot, X25519Slot

PUB_PREFIX = "clkpub1:"   # X25519 only (version 1.0.x)
PUB2_PREFIX = "clkpub2:"  # X25519 + Ed25519 signature-check key
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
    """A key pair: X25519 to receive files, plus an Ed25519 key to sign them.

    The signing key is derived from the same private key (HKDF with its own
    label), so existing key files can sign without any change.
    """
    private: X25519PrivateKey

    @property
    def public(self) -> X25519PublicKey:
        return self.private.public_key()

    @property
    def signing_key(self) -> Ed25519PrivateKey:
        raw = self.private.private_bytes(serialization.Encoding.Raw,
                                         serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption())
        seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"crunchlock ed25519 signing key v1").derive(raw)
        return Ed25519PrivateKey.from_private_bytes(seed)

    @property
    def verify_key(self) -> Ed25519PublicKey:
        return self.signing_key.public_key()


def generate_identity() -> Identity:
    return Identity(X25519PrivateKey.generate())


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def public_key_to_text(key: "Identity | X25519PublicKey") -> str:
    """Shareable public key. For an Identity this includes the signature-check key
    (``clkpub2:``); a bare X25519 key gives the older ``clkpub1:`` form."""
    if isinstance(key, Identity):
        return PUB2_PREFIX + _b64(key.public.public_bytes_raw() + key.verify_key.public_bytes_raw())
    return PUB_PREFIX + _b64(key.public_bytes_raw())


def parse_public_text(text: str) -> tuple[X25519PublicKey, Ed25519PublicKey | None]:
    text = text.strip()
    for prefix, size in ((PUB2_PREFIX, 64), (PUB_PREFIX, 32)):
        if text.startswith(prefix):
            break
    else:
        raise CrunchlockError("not a crunchlock public key (expected 'clkpub2:...' or 'clkpub1:...')")
    body = text[len(prefix):]
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except ValueError as e:
        raise CrunchlockError("malformed public key") from e
    if len(raw) != size:
        raise CrunchlockError("malformed public key")
    try:
        x = X25519PublicKey.from_public_bytes(raw[:32])
        ed = Ed25519PublicKey.from_public_bytes(raw[32:]) if size == 64 else None
    except ValueError as e:
        raise CrunchlockError("malformed public key") from e
    return x, ed


def public_key_from_text(text: str) -> X25519PublicKey:
    return parse_public_text(text)[0]


def verify_key_from_text(text: str) -> Ed25519PublicKey:
    ed = parse_public_text(text)[1]
    if ed is None:
        raise CrunchlockError("this public key (clkpub1) is from an older version and can't check "
                              "signatures; ask its owner for a new one (crunchlock pubkey)")
    return ed


def fingerprint(pub: "X25519PublicKey | Ed25519PublicKey | bytes") -> str:
    raw = pub if isinstance(pub, bytes) else pub.public_bytes_raw()
    h = hashes.Hash(hashes.SHA256())
    h.update(raw)
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
