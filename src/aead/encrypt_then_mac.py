import secrets

from cryptocore.csprng import generate_random_bytes
from cryptocore.modes import decrypt_ctr, encrypt_ctr
from mac import HMAC


NONCE_SIZE = 16
TAG_SIZE = 32
MASTER_KEY_SIZE = 16
DOMAIN = b"CryptoCore:EtM:v1"


class EtMAuthenticationError(ValueError):
    pass


def _ensure_bytes(value, name: str) -> bytes:
    if not isinstance(
        value,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError(f"{name} must be bytes-like")

    return bytes(value)


def _derive_key(master_key: bytes, label: bytes) -> bytes:
    mac = HMAC(master_key)
    mac.update(DOMAIN)
    mac.update(b":")
    mac.update(label)
    return mac.digest()


class EncryptThenMAC:
    nonce_size = NONCE_SIZE
    tag_size = TAG_SIZE

    def __init__(self, master_key: bytes) -> None:
        key = _ensure_bytes(master_key, "master_key")

        if len(key) != MASTER_KEY_SIZE:
            raise ValueError(
                "master key must contain exactly 16 bytes"
            )

        self._encryption_key = _derive_key(
            key, b"encryption"
        )[:16]

        self._authentication_key = _derive_key(
            key, b"authentication"
        )

        self._encryption_used = False

    def _calculate_tag(
        self,
        authenticated_ciphertext: bytes,
        aad: bytes,
    ) -> bytes:
        mac = HMAC(self._authentication_key)

        mac.update(DOMAIN)
        mac.update(
            len(authenticated_ciphertext).to_bytes(8, "big")
        )
        mac.update(authenticated_ciphertext)
        mac.update(len(aad).to_bytes(8, "big"))
        mac.update(aad)

        return mac.digest()

    def encrypt(
        self,
        plaintext: bytes,
        aad: bytes = b"",
        nonce: bytes | None = None,
    ) -> bytes:
        if self._encryption_used:
            raise ValueError(
                "encryption has already been performed "
                "with this instance"
            )

        plaintext = _ensure_bytes(plaintext, "plaintext")
        aad = _ensure_bytes(aad, "aad")

        if nonce is None:
            nonce = generate_random_bytes(NONCE_SIZE)
        else:
            nonce = _ensure_bytes(nonce, "nonce")

        if len(nonce) != NONCE_SIZE:
            raise ValueError(
                "nonce must contain exactly 16 bytes"
            )

        self._encryption_used = True

        ciphertext = encrypt_ctr(
            plaintext,
            self._encryption_key,
            nonce,
        )

        authenticated_ciphertext = nonce + ciphertext

        tag = self._calculate_tag(
            authenticated_ciphertext,
            aad,
        )

        return authenticated_ciphertext + tag

    def decrypt(
        self,
        data: bytes,
        aad: bytes = b"",
    ) -> bytes:
        data = _ensure_bytes(data, "data")
        aad = _ensure_bytes(aad, "aad")

        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise EtMAuthenticationError(
                "Authentication failed: invalid input length"
            )

        authenticated_ciphertext = data[:-TAG_SIZE]
        received_tag = data[-TAG_SIZE:]

        expected_tag = self._calculate_tag(
            authenticated_ciphertext,
            aad,
        )

        if not secrets.compare_digest(
            received_tag,
            expected_tag,
        ):
            raise EtMAuthenticationError(
                "Authentication failed: "
                "AAD mismatch or ciphertext tampered"
            )

        nonce = authenticated_ciphertext[:NONCE_SIZE]
        ciphertext = authenticated_ciphertext[NONCE_SIZE:]

        return decrypt_ctr(
            ciphertext,
            self._encryption_key,
            nonce,
        )