from hash import SHA256


BLOCK_SIZE = 64
IPAD = 0x36
OPAD = 0x5C


class HMAC:
    block_size = BLOCK_SIZE
    digest_size = 32

    def __init__(
        self,
        key: bytes
        | bytearray
        | memoryview,
    ) -> None:
        if not isinstance(
            key,
            (
                bytes,
                bytearray,
                memoryview,
            ),
        ):
            raise TypeError(
                "key must be bytes-like"
            )

        processed_key = (
            self._process_key(
                bytes(key)
            )
        )

        ipad = bytes(
            byte ^ IPAD
            for byte in processed_key
        )

        opad = bytes(
            byte ^ OPAD
            for byte in processed_key
        )

        self._inner = SHA256()
        self._inner.update(
            ipad
        )

        self._outer = SHA256()
        self._outer.update(
            opad
        )

    def _process_key(
        self,
        key: bytes,
    ) -> bytes:
        if len(key) > BLOCK_SIZE:
            hasher = SHA256()
            hasher.update(
                key
            )
            key = (
                hasher.digest()
            )

        if len(key) < BLOCK_SIZE:
            key = (
                key
                + b"\x00"
                * (
                    BLOCK_SIZE
                    - len(key)
                )
            )

        return key

    def copy(
        self,
    ) -> "HMAC":
        clone = object.__new__(
            self.__class__
        )

        clone._inner = (
            self._inner.copy()
        )

        clone._outer = (
            self._outer.copy()
        )

        return clone

    def update(
        self,
        data: bytes
        | bytearray
        | memoryview,
    ) -> "HMAC":
        if not isinstance(
            data,
            (
                bytes,
                bytearray,
                memoryview,
            ),
        ):
            raise TypeError(
                "data must be bytes-like"
            )

        self._inner.update(
            bytes(data)
        )

        return self

    def digest(
        self,
    ) -> bytes:
        inner = (
            self._inner.copy()
        )

        outer = (
            self._outer.copy()
        )

        inner_digest = (
            inner.digest()
        )

        outer.update(
            inner_digest
        )

        return (
            outer.digest()
        )

    def hexdigest(
        self,
    ) -> str:
        return (
            self.digest().hex()
        )

    @classmethod
    def compute(
        cls,
        key: bytes
        | bytearray
        | memoryview,
        data: bytes
        | bytearray
        | memoryview,
    ) -> str:
        instance = cls(
            key
        )

        instance.update(
            data
        )

        return (
            instance.hexdigest()
        )