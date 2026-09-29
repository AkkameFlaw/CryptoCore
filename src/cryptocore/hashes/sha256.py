from __future__ import annotations


MASK32 = 0xFFFFFFFF

INITIAL_HASH = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

ROUND_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotate_right(
    value: int,
    amount: int,
) -> int:
    return (
        (value >> amount)
        | (value << (32 - amount))
    ) & MASK32


class SHA256:
    block_size = 64
    digest_size = 32

    def __init__(
        self,
    ) -> None:
        self._h = list(
            INITIAL_HASH
        )

        self._buffer = bytearray()

        self._message_length = 0

    def copy(
            self,
    ) -> "SHA256":
        clone = self.__class__()

        clone._h = (
            self._h.copy()
        )

        clone._buffer = (
            self._buffer.copy()
        )

        clone._message_length = (
            self._message_length
        )

        return clone

    def update(
        self,
        data: bytes
        | bytearray
        | memoryview,
    ) -> SHA256:
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

        chunk = bytes(
            data
        )

        self._message_length += (
            len(chunk)
        )

        self._buffer.extend(
            chunk
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

            self._process_block(
                block
            )

        return self

    def _process_block(
        self,
        block: bytes,
    ) -> None:
        if (
            len(block)
            != self.block_size
        ):
            raise ValueError(
                "SHA-256 block must be "
                "exactly 64 bytes"
            )

        words = [0] * 64

        for index in range(16):
            start = index * 4

            words[index] = (
                int.from_bytes(
                    block[
                        start:start + 4
                    ],
                    "big",
                )
            )

        for index in range(
            16,
            64,
        ):
            x = words[
                index - 15
            ]

            y = words[
                index - 2
            ]

            sigma0 = (
                _rotate_right(
                    x,
                    7,
                )
                ^ _rotate_right(
                    x,
                    18,
                )
                ^ (x >> 3)
            )

            sigma1 = (
                _rotate_right(
                    y,
                    17,
                )
                ^ _rotate_right(
                    y,
                    19,
                )
                ^ (y >> 10)
            )

            words[index] = (
                words[index - 16]
                + sigma0
                + words[index - 7]
                + sigma1
            ) & MASK32

        (
            a,
            b,
            c,
            d,
            e,
            f,
            g,
            h,
        ) = self._h

        for index in range(64):
            sum1 = (
                _rotate_right(
                    e,
                    6,
                )
                ^ _rotate_right(
                    e,
                    11,
                )
                ^ _rotate_right(
                    e,
                    25,
                )
            )

            choice = (
                (e & f)
                ^ ((~e) & g)
            ) & MASK32

            temp1 = (
                h
                + sum1
                + choice
                + ROUND_CONSTANTS[
                    index
                ]
                + words[index]
            ) & MASK32

            sum0 = (
                _rotate_right(
                    a,
                    2,
                )
                ^ _rotate_right(
                    a,
                    13,
                )
                ^ _rotate_right(
                    a,
                    22,
                )
            )

            majority = (
                (a & b)
                ^ (a & c)
                ^ (b & c)
            ) & MASK32

            temp2 = (
                sum0
                + majority
            ) & MASK32

            h = g
            g = f
            f = e

            e = (
                d
                + temp1
            ) & MASK32

            d = c
            c = b
            b = a

            a = (
                temp1
                + temp2
            ) & MASK32

        self._h[0] = (
            self._h[0] + a
        ) & MASK32

        self._h[1] = (
            self._h[1] + b
        ) & MASK32

        self._h[2] = (
            self._h[2] + c
        ) & MASK32

        self._h[3] = (
            self._h[3] + d
        ) & MASK32

        self._h[4] = (
            self._h[4] + e
        ) & MASK32

        self._h[5] = (
            self._h[5] + f
        ) & MASK32

        self._h[6] = (
            self._h[6] + g
        ) & MASK32

        self._h[7] = (
            self._h[7] + h
        ) & MASK32

    def _finalize(
        self,
    ) -> None:
        bit_length = (
            self._message_length * 8
        ) & 0xFFFFFFFFFFFFFFFF

        self._buffer.append(
            0x80
        )

        while (
            len(self._buffer)
            % self.block_size
            != 56
        ):
            self._buffer.append(
                0
            )

        self._buffer.extend(
            bit_length.to_bytes(
                8,
                "big",
            )
        )

        while self._buffer:
            block = bytes(
                self._buffer[
                    :self.block_size
                ]
            )

            del self._buffer[
                :self.block_size
            ]

            self._process_block(
                block
            )

    def digest(
        self,
    ) -> bytes:
        clone = self.copy()

        clone._finalize()

        return b"".join(
            value.to_bytes(
                4,
                "big",
            )
            for value in clone._h
        )

    def hexdigest(
        self,
    ) -> str:
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
        instance = cls()

        instance.update(
            data
        )

        return (
            instance.hexdigest()
        )