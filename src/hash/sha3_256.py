"""Pure-Python streaming SHA3-256 (FIPS 202)."""

MASK64 = 0xFFFFFFFFFFFFFFFF

ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

ROTATION_OFFSETS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)


def _rotate_left(
    value: int,
    amount: int,
) -> int:
    """Rotate a 64-bit word left.
    
        Args:
            value: Input word or field element.
            amount: Number of bits to rotate.
    
        Returns:
            Integer result or process exit code.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
    if amount == 0:
        return value & MASK64

    return (
        (value << amount)
        | (value >> (64 - amount))
    ) & MASK64


def _keccak_f(
    state: list[int],
) -> None:
    """Apply the Keccak-f[1600] permutation.
    
        Args:
            state: Parameter used by this operation; see docs/API.md.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
    for round_constant in ROUND_CONSTANTS:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]

        differences = [
            columns[(x - 1) % 5]
            ^ _rotate_left(
                columns[(x + 1) % 5],
                1,
            )
            for x in range(5)
        ]

        for y in range(5):
            for x in range(5):
                state[
                    x + 5 * y
                ] ^= differences[x]

        transformed = [0] * 25

        for y in range(5):
            for x in range(5):
                new_x = y
                new_y = (
                    2 * x
                    + 3 * y
                ) % 5

                transformed[
                    new_x + 5 * new_y
                ] = _rotate_left(
                    state[x + 5 * y],
                    ROTATION_OFFSETS[
                        x + 5 * y
                    ],
                )

        for y in range(5):
            row = 5 * y

            for x in range(5):
                state[
                    row + x
                ] = (
                    transformed[
                        row + x
                    ]
                    ^ (
                        ~transformed[
                            row + (
                                (x + 1) % 5
                            )
                        ]
                        & transformed[
                            row + (
                                (x + 2) % 5
                            )
                        ]
                    )
                ) & MASK64

        state[0] ^= round_constant


class SHA3_256:
    """Incremental SHA3-256 hash context.

    Notes:
        Consult docs/API.md for construction, safety, and examples.
    """
    block_size = 136
    digest_size = 32

    def __init__(
        self,
    ) -> None:
        """Construct the object and validate initialization parameters.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
        self._state = [0] * 25
        self._buffer = bytearray()

    def copy(
        self,
    ) -> "SHA3_256":
        """Return an independent copy of the current hashing or MAC state.
    
        Returns:
            A value of type 'SHA3_256'; see docs/API.md.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
        clone = self.__class__()

        clone._state = (
            self._state.copy()
        )

        clone._buffer = (
            self._buffer.copy()
        )

        return clone

    def update(
        self,
        data: bytes
        | bytearray
        | memoryview,
    ) -> "SHA3_256":
        """Absorb additional binary input and return the updated object.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
    
        Returns:
            A value of type 'SHA3_256'; see docs/API.md.
    
        Raises:
            TypeError on non-bytes-like update data.
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

        self._buffer.extend(
            bytes(data)
        )

        while (
            len(self._buffer)
            >= self.block_size
        ):
            block = bytes(
                self._buffer[
                    :self.block_size
                ]
            )

            del self._buffer[
                :self.block_size
            ]

            self._absorb_block(
                block
            )

        return self

    def _absorb_block(
        self,
        block: bytes,
    ) -> None:
        """Perform the  absorb block operation in hash.sha3_256.
    
        Args:
            block: Parameter used by this operation; see docs/API.md.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
        if (
            len(block)
            != self.block_size
        ):
            raise ValueError(
                "SHA3-256 block must be "
                "exactly 136 bytes"
            )

        lane_count = (
            self.block_size // 8
        )

        for index in range(
            lane_count
        ):
            start = index * 8

            lane = int.from_bytes(
                block[
                    start:start + 8
                ],
                "little",
            )

            self._state[index] ^= lane

        _keccak_f(
            self._state
        )

    def _finalize(
        self,
    ) -> None:
        """Perform the  finalize operation in hash.sha3_256.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
        padding_length = (
            self.block_size
            - len(self._buffer)
        )

        self._buffer.append(
            0x06
        )

        if padding_length > 1:
            self._buffer.extend(
                b"\x00"
                * (
                    padding_length - 1
                )
            )

        self._buffer[-1] |= (
            0x80
        )

        block = bytes(
            self._buffer
        )

        self._buffer.clear()

        self._absorb_block(
            block
        )

    def digest(
        self,
    ) -> bytes:
        """Return final digest bytes without modifying the original state.
    
        Returns:
            Binary result.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
        clone = self.copy()

        clone._finalize()

        output = b"".join(
            lane.to_bytes(
                8,
                "little",
            )
            for lane in clone._state
        )

        return output[
            :self.digest_size
        ]

    def hexdigest(
        self,
    ) -> str:
        """Return the digest as a lowercase HEX string.
    
        Returns:
            Text output.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
        return (
            self.digest().hex()
        )

    @classmethod
    def hash(
        cls,
        data: bytes
        | bytearray
        | memoryview,
    ) -> str:
        """Compute the digest of supplied data (class convenience method).
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
    
        Returns:
            Text output.
    
        Raises:
            TypeError on non-bytes-like update data.
    """
        instance = cls()

        instance.update(
            data
        )

        return (
            instance.hexdigest()
        )