import pytest

from mac import HMAC


@pytest.mark.parametrize(
    (
        "key",
        "data",
        "expected",
    ),
    [
        (
            bytes.fromhex(
                "0b" * 20
            ),
            b"Hi There",
            (
                "b0344c61d8db38535ca8afceaf0bf12b"
                "881dc200c9833da726e9376c2e32cff7"
            ),
        ),
        (
            b"Jefe",
            (
                b"what do ya want "
                b"for nothing?"
            ),
            (
                "5bdcc146bf60754e6a042426089575c75"
                "a003f089d2739839dec58b964ec3843"
            ),
        ),
        (
            bytes.fromhex(
                "aa" * 20
            ),
            bytes.fromhex(
                "dd" * 50
            ),
            (
                "773ea91e36800e46854db8ebd09181a7"
                "2959098b3ef8c122d9635514ced565fe"
            ),
        ),
        (
            bytes.fromhex(
                "".join(
                    f"{value:02x}"
                    for value in range(
                        1,
                        26
                    )
                )
            ),
            bytes.fromhex(
                "cd" * 50
            ),
            (
                "82558a389a443c0ea4cc819899f2083a"
                "85f0faa3e578f8077a2e3ff46729665b"
            ),
        ),
    ],
)
def test_rfc_4231_vectors(
    key: bytes,
    data: bytes,
    expected: str,
) -> None:
    assert (
        HMAC.compute(
            key,
            data,
        )
        == expected
    )


def test_hmac_short_key(
) -> None:
    key = (
        b"K" * 16
    )

    result = HMAC.compute(
        key,
        b"CryptoCore"
    )

    assert len(result) == 64


def test_hmac_block_sized_key(
) -> None:
    key = (
        b"K" * 64
    )

    result = HMAC.compute(
        key,
        b"CryptoCore"
    )

    assert len(result) == 64


def test_hmac_long_key(
) -> None:
    key = (
        b"K" * 100
    )

    result = HMAC.compute(
        key,
        b"CryptoCore"
    )

    assert len(result) == 64


def test_hmac_empty_message(
) -> None:
    result = HMAC.compute(
        b"secret",
        b"",
    )

    assert len(result) == 64


def test_hmac_incremental(
) -> None:
    hmac = HMAC(
        b"secret"
    )

    hmac.update(
        b"Crypto"
    )

    hmac.update(
        b"Core"
    )

    assert (
        hmac.hexdigest()
        == HMAC.compute(
            b"secret",
            b"CryptoCore",
        )
    )


def test_hmac_invalid_key_type(
) -> None:
    with pytest.raises(
        TypeError
    ):
        HMAC(
            "secret"
        )


def test_hmac_invalid_data_type(
) -> None:
    hmac = HMAC(
        b"secret"
    )

    with pytest.raises(
        TypeError
    ):
        hmac.update(
            "data"
        )