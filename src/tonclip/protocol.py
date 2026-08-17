import base64
import binascii
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_PREFIX = "tonclip1_"
RECORD_VERSION = 1
RECORD_SIZE = 768
KEY_SIZE = 32
CHECKSUM_SIZE = 4
NONCE_SIZE = 12
TAG_SIZE = 16
LENGTH_SIZE = 2
MAX_PAYLOAD_SIZE = RECORD_SIZE - 1 - NONCE_SIZE - TAG_SIZE - LENGTH_SIZE
RECORD_AAD = b"tonclip/v1/record"


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ClipKey:
    seed: bytes

    def __post_init__(self) -> None:
        if len(self.seed) != KEY_SIZE:
            raise ProtocolError("invalid key seed")

    @classmethod
    def generate(cls) -> "ClipKey":
        return cls(os.urandom(KEY_SIZE))

    @classmethod
    def parse(cls, value: str) -> "ClipKey":
        value = value.strip()
        if not value.startswith(KEY_PREFIX):
            raise ProtocolError("not a tonclip key")
        encoded = value[len(KEY_PREFIX) :]
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, binascii.Error) as exc:
            raise ProtocolError("invalid tonclip key") from exc
        if len(raw) != KEY_SIZE + CHECKSUM_SIZE:
            raise ProtocolError("invalid tonclip key")
        expected = _checksum(raw[:KEY_SIZE])
        if not hmac.compare_digest(raw[KEY_SIZE:], expected):
            raise ProtocolError("invalid tonclip key checksum")
        return cls(raw[:KEY_SIZE])

    def __str__(self) -> str:
        raw = self.seed + _checksum(self.seed)
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        return KEY_PREFIX + encoded

    def signing_seed(self) -> bytes:
        return _derive(self.seed, b"tonclip/v1/signing")

    def encryption_key(self) -> bytes:
        return _derive(self.seed, b"tonclip/v1/encryption")

    def encrypt(self, payload: bytes) -> bytes:
        if not payload:
            raise ProtocolError("nothing to store")
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise ProtocolError(
                f"payload is {len(payload)} bytes; tonclip holds at most {MAX_PAYLOAD_SIZE}"
            )
        plaintext_size = RECORD_SIZE - 1 - NONCE_SIZE - TAG_SIZE
        plaintext = bytearray(os.urandom(plaintext_size))
        plaintext[:LENGTH_SIZE] = struct.pack(">H", len(payload))
        plaintext[LENGTH_SIZE : LENGTH_SIZE + len(payload)] = payload
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(self.encryption_key()).encrypt(
            nonce, bytes(plaintext), RECORD_AAD
        )
        record = bytes([RECORD_VERSION]) + nonce + ciphertext
        if len(record) != RECORD_SIZE:
            raise RuntimeError("invalid encrypted record size")
        return record

    def decrypt(self, record: bytes) -> bytes:
        if len(record) != RECORD_SIZE or record[0] != RECORD_VERSION:
            raise ProtocolError("unsupported or malformed tonclip record")
        nonce = record[1 : 1 + NONCE_SIZE]
        try:
            plaintext = AESGCM(self.encryption_key()).decrypt(
                nonce, record[1 + NONCE_SIZE :], RECORD_AAD
            )
        except InvalidTag as exc:
            raise ProtocolError("tonclip record failed authentication") from exc
        length = struct.unpack(">H", plaintext[:LENGTH_SIZE])[0]
        if length > MAX_PAYLOAD_SIZE:
            raise ProtocolError("malformed tonclip payload length")
        return plaintext[LENGTH_SIZE : LENGTH_SIZE + length]


def _derive(seed: bytes, label: bytes) -> bytes:
    return hmac.new(seed, label, hashlib.sha256).digest()


def _checksum(seed: bytes) -> bytes:
    return hashlib.sha256(b"tonclip/v1/key" + seed).digest()[:CHECKSUM_SIZE]
