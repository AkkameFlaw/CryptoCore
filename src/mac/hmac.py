"""Pure-Python HMAC-SHA256 implemented using the local SHA256 class."""

from hash import SHA256


BLOCK_SIZE = 64
IPAD = 0x36
OPAD = 0x5C


class HMAC:
    """Incremental HMAC-SHA256 context using the bundled SHA256 algorithm.

    Notes:
        Consult docs/API.md for construction, safety, and examples.
    """
    block_size = BLOCK_SIZE
    digest_size = 32

    def __init__(
        self,
        key: bytes
        | bytearray
        | memoryview,
    ) -> None:
        """Construct the object and validate initialization parameters.
    
        Args:
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            TypeError on unsupported key or data type.
    """
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
        """Normalize HMAC key to one 64-byte SHA-256 block.
    
        Args:
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Binary result.
    
        Raises:
            TypeError on unsupported key or data type.
    """
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
        """Return an independent copy of the current hashing or MAC state.
    
        Returns:
            A value of type 'HMAC'; see docs/API.md.
    
        Raises:
            TypeError on unsupported key or data type.
    """
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
        """Absorb additional binary input and return the updated object.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
    
        Returns:
            A value of type 'HMAC'; see docs/API.md.
    
        Raises:
            TypeError on unsupported key or data type.
    """
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
        """Return final digest bytes without modifying the original state.
    
        Returns:
            Binary result.
    
        Raises:
            TypeError on unsupported key or data type.
    """
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
        """Return the digest as a lowercase HEX string.
    
        Returns:
            Text output.
    
        Raises:
            TypeError on unsupported key or data type.
    """
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
        """Compute an HMAC and return its lowercase HEX representation.
    
        Args:
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            data: Binary input; for ciphertext, the format depends on the selected mode.
    
        Returns:
            Text output.
    
        Raises:
            TypeError on unsupported key or data type.
    """
        instance = cls(
            key
        )

        instance.update(
            data
        )

        return (
            instance.hexdigest()
        )