"""Demo: SHA, HMAC, PBKDF2, GCM and EtM on nonsecret test data."""

from aead import EncryptThenMAC
from hash import SHA256, SHA3_256
from kdf import derive_key, pbkdf2_hmac_sha256
from mac import HMAC
from modes import GCM


def main() -> None:
    """Print verifiable results using public APIs and a fixed test key."""
    payload = b"Demo message"
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    print("SHA256:", SHA256.hash(payload).hex() if isinstance(SHA256.hash(payload), bytes) else SHA256.hash(payload))
    print("SHA3:", SHA3_256.hash(payload).hex() if isinstance(SHA3_256.hash(payload), bytes) else SHA3_256.hash(payload))
    print("HMAC:", HMAC.compute(key, payload))
    print("PBKDF2:", pbkdf2_hmac_sha256(b"password", b"salt", 2, 16).hex())
    print("Derived:", derive_key(key, "encryption", 16).hex())
    gcm_payload = GCM(key).encrypt(payload, aad=b"meta")
    assert GCM(key, gcm_payload[:12]).decrypt(gcm_payload, aad=b"meta") == payload
    etm_payload = EncryptThenMAC(key).encrypt(payload, aad=b"meta")
    assert EncryptThenMAC(key).decrypt(etm_payload, aad=b"meta") == payload
    print("GCM: OK; EtM: OK")


if __name__ == "__main__":
    main()
