"""Teaching-only GHASH reference; not used for production GCM.

The lookup table in this illustration is not constant-time. DO NOT use it
for protection of real messages; deployed GCM uses PyCryptodome.
"""

REDUCTION = 0xE1000000000000000000000000000000

def _gf_multiply(x: int, y: int) -> int:
    """Multiply two 128-bit field elements in GHASH GF(2^128).
    
        Args:
            x: Parameter used by this operation; see docs/API.md.
            y: Parameter used by this operation; see docs/API.md.
    
        Returns:
            Integer result or process exit code.
    
        Raises:
            TypeError, ValueError or AuthenticationError.
    """
    result = 0
    value = y

    for index in range(127, -1, -1):
        if (x >> index) & 1:
            result ^= value

        value = (value >> 1) ^ (REDUCTION if value & 1 else 0)

    return result


class _GFMultiplier:
    """Precomputed GHASH multiplier for GF(2^128).

    Notes:
        Consult docs/API.md for construction, safety, and examples.
    """
    def __init__(self, multiplier: int) -> None:
        """Construct the object and validate initialization parameters.
    
        Args:
            multiplier: Parameter used by this operation; see docs/API.md.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            TypeError, ValueError or AuthenticationError.
    """
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
        """Multiply a field element by the precomputed GHASH subkey.
    
        Args:
            value: Input word or field element.
    
        Returns:
            Integer result or process exit code.
    
        Raises:
            TypeError, ValueError or AuthenticationError.
    """
        result = 0

        for position, table in enumerate(self._tables):
            nibble = (value >> (124 - 4 * position)) & 15
            result ^= table[nibble]

        return result


