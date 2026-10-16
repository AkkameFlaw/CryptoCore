import secrets
from typing import BinaryIO

from Crypto.Cipher import AES

from cryptocore.csprng import generate_random_bytes


REDUCTION = 0xE1000000000000000000000000000000
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 8192


class AuthenticationError(ValueError):
    pass


def _gf_multiply(x: int, y: int) -> int:
    result = 0
    value = y

    for index in range(127, -1, -1):
        if (x >> index) & 1:
            result ^= value

        value = (value >> 1) ^ (REDUCTION if value & 1 else 0)

    return result


class _GFMultiplier:
    def __init__(self, multiplier: int) -> None:
        contributions = []
        value = multiplier

        for _ in range(128):
            contributions.append(value)
            value = (value >> 1) ^ (REDUCTION if value & 1 else 0)

        self._tables = []

        for position in range(32):
            values = contributions[position * 4:position * 4 + 4]
            table = []

            for nibble in range(16):
                entry = 0

                for bit in range(4):
                    if nibble & (8 >> bit):
                        entry ^= values[bit]

                table.append(entry)

            self._tables.append(table)

    def multiply(self, value: int) -> int:
        result = 0

        for position, table in enumerate(self._tables):
            nibble = (value >> (124 - 4 * position)) & 15
            result ^= table[nibble]

        return result


class GCM:
    tag_size = TAG_SIZE
    nonce_size = NONCE_SIZE

    def __init__(self, key: bytes, nonce: bytes | None = None) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")

        if len(key) != 16:
            raise ValueError("AES-128 key must be exactly 16 bytes")

        if nonce is None:
            nonce = generate_random_bytes(NONCE_SIZE)

        if not isinstance(nonce, (bytes, bytearray, memoryview)):
            raise TypeError("nonce must be bytes-like")

        if not nonce:
            raise ValueError("nonce must not be empty")

        self.nonce = bytes(nonce)
        self._aes = AES.new(bytes(key), AES.MODE_ECB)

        subkey = int.from_bytes(
            self._aes.encrypt(bytes(16)),
            "big",
        )

        self._multiplier = _GFMultiplier(subkey)
        self._j0 = self._initial_counter()
        self._encryption_used = False

    def _initial_counter(self) -> bytes:
        if len(self.nonce) == NONCE_SIZE:
            return self.nonce + b"\x00\x00\x00\x01"

        return self._ghash(b"", self.nonce)

    @staticmethod
    def _increment_counter(block: bytes) -> bytes:
        counter = (
            int.from_bytes(block[12:], "big") + 1
        ) & 0xFFFFFFFF

        return block[:12] + counter.to_bytes(4, "big")

    def _counter_crypt(self, data: bytes) -> bytes:
        if len(data) > ((1 << 32) - 2) * 16:
            raise ValueError("GCM input exceeds counter limit")

        counter = self._j0
        result = bytearray()

        for offset in range(0, len(data), 16):
            counter = self._increment_counter(counter)
            mask = self._aes.encrypt(counter)
            block = data[offset:offset + 16]

            result.extend(
                left ^ right
                for left, right in zip(block, mask)
            )

        return bytes(result)

    @staticmethod
    def _iter_chunks(source: bytes | BinaryIO):
        if isinstance(source, (bytes, bytearray, memoryview)):
            data = memoryview(source)

            for offset in range(0, len(data), CHUNK_SIZE):
                yield data[offset:offset + CHUNK_SIZE]

        elif hasattr(source, "read"):
            while True:
                chunk = source.read(CHUNK_SIZE)

                if not chunk:
                    break

                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise TypeError("AAD stream must return bytes")

                yield chunk

        else:
            raise TypeError(
                "AAD must be bytes-like or a binary stream"
            )

    def _ghash_input(
        self,
        accumulator: int,
        source: bytes | BinaryIO,
    ) -> tuple[int, int]:
        remainder = b""
        total = 0

        for chunk in self._iter_chunks(source):
            total += len(chunk)
            data = remainder + bytes(chunk)
            complete = (len(data) // 16) * 16

            for offset in range(0, complete, 16):
                block = int.from_bytes(
                    data[offset:offset + 16],
                    "big",
                )

                accumulator = self._multiplier.multiply(
                    accumulator ^ block
                )

            remainder = data[complete:]

        if remainder:
            block = int.from_bytes(
                remainder.ljust(16, b"\x00"),
                "big",
            )

            accumulator = self._multiplier.multiply(
                accumulator ^ block
            )

        return accumulator, total

    def _ghash(
        self,
        aad: bytes | BinaryIO,
        ciphertext: bytes,
    ) -> bytes:
        accumulator, aad_size = self._ghash_input(0, aad)

        accumulator, ciphertext_size = self._ghash_input(
            accumulator,
            ciphertext,
        )

        if aad_size >= (1 << 61) or ciphertext_size >= (1 << 61):
            raise ValueError(
                "GCM length exceeds 64-bit bit-length field"
            )

        lengths = (
            (aad_size * 8) << 64
        ) | (ciphertext_size * 8)

        accumulator = self._multiplier.multiply(
            accumulator ^ lengths
        )

        return accumulator.to_bytes(16, "big")

    def encrypt(
        self,
        plaintext: bytes,
        aad: bytes | BinaryIO = b"",
    ) -> bytes:
        if self._encryption_used:
            raise ValueError(
                "nonce has already been used for encryption"
            )

        if not isinstance(
            plaintext,
            (bytes, bytearray, memoryview),
        ):
            raise TypeError("plaintext must be bytes-like")

        self._encryption_used = True

        ciphertext = self._counter_crypt(bytes(plaintext))
        authenticator = self._ghash(aad, ciphertext)
        mask = self._aes.encrypt(self._j0)

        tag = bytes(
            left ^ right
            for left, right in zip(mask, authenticator)
        )

        return self.nonce + ciphertext + tag

    def decrypt(
        self,
        data: bytes,
        aad: bytes | BinaryIO = b"",
        includes_nonce: bool = True,
    ) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")

        payload = bytes(data)

        if includes_nonce:
            if len(payload) < len(self.nonce) + TAG_SIZE:
                raise AuthenticationError(
                    "Authentication failed: invalid input length"
                )

            if not secrets.compare_digest(
                payload[:len(self.nonce)],
                self.nonce,
            ):
                raise AuthenticationError(
                    "Authentication failed: nonce mismatch"
                )

            payload = payload[len(self.nonce):]

        if len(payload) < TAG_SIZE:
            raise AuthenticationError(
                "Authentication failed: missing tag"
            )

        ciphertext = payload[:-TAG_SIZE]
        received_tag = payload[-TAG_SIZE:]

        authenticator = self._ghash(aad, ciphertext)
        mask = self._aes.encrypt(self._j0)

        expected_tag = bytes(
            left ^ right
            for left, right in zip(mask, authenticator)
        )

        if not secrets.compare_digest(
            received_tag,
            expected_tag,
        ):
            raise AuthenticationError(
                "Authentication failed: AAD mismatch or ciphertext tampered"
            )

        return self._counter_crypt(ciphertext)