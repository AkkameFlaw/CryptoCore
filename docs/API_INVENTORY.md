# CryptoCore API Inventory

Generated from source files using Python AST.

Definitions found: 87

Missing docstrings: 0

This inventory includes all non-private definitions.
It must be reviewed before deciding which objects belong to the supported public API.

### `aead.encrypt_then_mac.EncryptThenMAC`

Signature: `class EncryptThenMAC`

Source: `src/aead/encrypt_then_mac.py:67`

Docstring: **Present**

### `aead.encrypt_then_mac.EncryptThenMAC.__init__`

Signature: `__init__(self, master_key: bytes) -> None`

Source: `src/aead/encrypt_then_mac.py:76`

Docstring: **Present**

### `aead.encrypt_then_mac.EncryptThenMAC.decrypt`

Signature: `decrypt(self, data: bytes, aad: bytes=b'') -> bytes`

Source: `src/aead/encrypt_then_mac.py:192`

Docstring: **Present**

### `aead.encrypt_then_mac.EncryptThenMAC.encrypt`

Signature: `encrypt(self, plaintext: bytes, aad: bytes=b'', nonce: bytes | None=None) -> bytes`

Source: `src/aead/encrypt_then_mac.py:134`

Docstring: **Present**

### `aead.encrypt_then_mac.EtMAuthenticationError`

Signature: `class EtMAuthenticationError`

Source: `src/aead/encrypt_then_mac.py:16`

Docstring: **Present**

### `cryptocore.cli.ArgumentError`

Signature: `class ArgumentError`

Source: `src/cryptocore/cli.py:57`

Docstring: **Present**

### `cryptocore.cli.build_derive_parser`

Signature: `build_derive_parser() -> argparse.ArgumentParser`

Source: `src/cryptocore/cli.py:130`

Docstring: **Present**

### `cryptocore.cli.build_digest_parser`

Signature: `build_digest_parser() -> argparse.ArgumentParser`

Source: `src/cryptocore/cli.py:106`

Docstring: **Present**

### `cryptocore.cli.build_parser`

Signature: `build_parser() -> argparse.ArgumentParser`

Source: `src/cryptocore/cli.py:66`

Docstring: **Present**

### `cryptocore.cli.decrypt_data`

Signature: `decrypt_data(data: bytes, key: bytes, mode: str, iv_text: str | None, aad: bytes | BinaryIO=b'', nonce_text: str | None=None) -> bytes`

Source: `src/cryptocore/cli.py:613`

Docstring: **Present**

### `cryptocore.cli.encrypt_data`

Signature: `encrypt_data(data: bytes, key: bytes, mode: str, aad: bytes | BinaryIO=b'') -> bytes`

Source: `src/cryptocore/cli.py:564`

Docstring: **Present**

### `cryptocore.cli.get_default_output`

Signature: `get_default_output(input_file: str, decrypt: bool) -> str`

Source: `src/cryptocore/cli.py:475`

Docstring: **Present**

### `cryptocore.cli.is_weak_key`

Signature: `is_weak_key(key: bytes) -> bool`

Source: `src/cryptocore/cli.py:400`

Docstring: **Present**

### `cryptocore.cli.main`

Signature: `main() -> int`

Source: `src/cryptocore/cli.py:974`

Docstring: **Present**

### `cryptocore.cli.parse_aad`

Signature: `parse_aad(aad_text: str | None) -> bytes`

Source: `src/cryptocore/cli.py:299`

Docstring: **Present**

### `cryptocore.cli.parse_hmac_key`

Signature: `parse_hmac_key(key_text: str) -> bytes`

Source: `src/cryptocore/cli.py:216`

Docstring: **Present**

### `cryptocore.cli.parse_iv`

Signature: `parse_iv(iv_text: str) -> bytes`

Source: `src/cryptocore/cli.py:239`

Docstring: **Present**

### `cryptocore.cli.parse_key`

Signature: `parse_key(key_text: str) -> bytes`

Source: `src/cryptocore/cli.py:184`

Docstring: **Present**

### `cryptocore.cli.parse_nonce`

Signature: `parse_nonce(nonce_text: str) -> bytes`

Source: `src/cryptocore/cli.py:271`

Docstring: **Present**

### `cryptocore.cli.resolve_key`

Signature: `resolve_key(args: argparse.Namespace) -> bytes`

Source: `src/cryptocore/cli.py:442`

Docstring: **Present**

### `cryptocore.cli.resolve_password`

Signature: `resolve_password(args: argparse.Namespace) -> bytearray`

Source: `src/cryptocore/cli.py:351`

Docstring: **Present**

### `cryptocore.cli.resolve_salt`

Signature: `resolve_salt(salt_text: str | None) -> bytes`

Source: `src/cryptocore/cli.py:325`

Docstring: **Present**

### `cryptocore.cli.run`

Signature: `run(argv: list[str] | None=None) -> int`

Source: `src/cryptocore/cli.py:888`

Docstring: **Present**

### `cryptocore.cli.run_derive`

Signature: `run_derive(argv: list[str]) -> int`

Source: `src/cryptocore/cli.py:788`

Docstring: **Present**

### `cryptocore.cli.run_digest`

Signature: `run_digest(argv: list[str]) -> int`

Source: `src/cryptocore/cli.py:694`

Docstring: **Present**

### `cryptocore.cli.validate_arguments`

Signature: `validate_arguments(args: argparse.Namespace) -> str`

Source: `src/cryptocore/cli.py:494`

Docstring: **Present**

### `cryptocore.csprng.generate_random_bytes`

Signature: `generate_random_bytes(num_bytes: int) -> bytes`

Source: `src/cryptocore/csprng.py:6`

Docstring: **Present**

### `cryptocore.digest.create_hasher`

Signature: `create_hasher(algorithm: str) -> unspecified`

Source: `src/cryptocore/digest.py:18`

Docstring: **Present**

### `cryptocore.digest.format_digest`

Signature: `format_digest(hash_value: str, input_file: str) -> str`

Source: `src/cryptocore/digest.py:181`

Docstring: **Present**

### `cryptocore.digest.format_hmac`

Signature: `format_hmac(hmac_value: str, input_file: str) -> str`

Source: `src/cryptocore/digest.py:203`

Docstring: **Present**

### `cryptocore.digest.hash_file`

Signature: `hash_file(input_file: str, algorithm: str) -> str`

Source: `src/cryptocore/digest.py:82`

Docstring: **Present**

### `cryptocore.digest.hash_stream`

Signature: `hash_stream(stream: BinaryIO, algorithm: str) -> str`

Source: `src/cryptocore/digest.py:47`

Docstring: **Present**

### `cryptocore.digest.hmac_file`

Signature: `hmac_file(input_file: str, key: bytes) -> str`

Source: `src/cryptocore/digest.py:149`

Docstring: **Present**

### `cryptocore.digest.hmac_stream`

Signature: `hmac_stream(stream: BinaryIO, key: bytes) -> str`

Source: `src/cryptocore/digest.py:114`

Docstring: **Present**

### `cryptocore.digest.read_expected_hmac`

Signature: `read_expected_hmac(input_file: str) -> str`

Source: `src/cryptocore/digest.py:225`

Docstring: **Present**

### `cryptocore.digest.write_digest_output`

Signature: `write_digest_output(output_file: str, result: str) -> None`

Source: `src/cryptocore/digest.py:278`

Docstring: **Present**

### `cryptocore.file_io.read_binary`

Signature: `read_binary(path: str | Path) -> bytes`

Source: `src/cryptocore/file_io.py:6`

Docstring: **Present**

### `cryptocore.file_io.write_binary`

Signature: `write_binary(path: str | Path, data: bytes) -> None`

Source: `src/cryptocore/file_io.py:23`

Docstring: **Present**

### `cryptocore.modes.cbc.decrypt_cbc`

Signature: `decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/cbc.py:77`

Docstring: **Present**

### `cryptocore.modes.cbc.encrypt_cbc`

Signature: `encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/cbc.py:18`

Docstring: **Present**

### `cryptocore.modes.cfb.decrypt_cfb`

Signature: `decrypt_cfb(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/cfb.py:70`

Docstring: **Present**

### `cryptocore.modes.cfb.encrypt_cfb`

Signature: `encrypt_cfb(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/cfb.py:13`

Docstring: **Present**

### `cryptocore.modes.common.validate_iv`

Signature: `validate_iv(iv: bytes) -> None`

Source: `src/cryptocore/modes/common.py:24`

Docstring: **Present**

### `cryptocore.modes.common.validate_key`

Signature: `validate_key(key: bytes) -> None`

Source: `src/cryptocore/modes/common.py:6`

Docstring: **Present**

### `cryptocore.modes.common.xor_bytes`

Signature: `xor_bytes(left: bytes, right: bytes) -> bytes`

Source: `src/cryptocore/modes/common.py:42`

Docstring: **Present**

### `cryptocore.modes.ctr.decrypt_ctr`

Signature: `decrypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/ctr.py:108`

Docstring: **Present**

### `cryptocore.modes.ctr.encrypt_ctr`

Signature: `encrypt_ctr(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/ctr.py:83`

Docstring: **Present**

### `cryptocore.modes.ctr.process_ctr`

Signature: `process_ctr(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/ctr.py:16`

Docstring: **Present**

### `cryptocore.modes.ecb.PaddingError`

Signature: `class PaddingError`

Source: `src/cryptocore/modes/ecb.py:11`

Docstring: **Present**

### `cryptocore.modes.ecb.decrypt_ecb`

Signature: `decrypt_ecb(data: bytes, key: bytes) -> bytes`

Source: `src/cryptocore/modes/ecb.py:151`

Docstring: **Present**

### `cryptocore.modes.ecb.encrypt_ecb`

Signature: `encrypt_ecb(data: bytes, key: bytes) -> bytes`

Source: `src/cryptocore/modes/ecb.py:108`

Docstring: **Present**

### `cryptocore.modes.ecb.pkcs7_pad`

Signature: `pkcs7_pad(data: bytes, block_size: int=BLOCK_SIZE) -> bytes`

Source: `src/cryptocore/modes/ecb.py:20`

Docstring: **Present**

### `cryptocore.modes.ecb.pkcs7_unpad`

Signature: `pkcs7_unpad(data: bytes, block_size: int=BLOCK_SIZE) -> bytes`

Source: `src/cryptocore/modes/ecb.py:52`

Docstring: **Present**

### `cryptocore.modes.ofb.decrypt_ofb`

Signature: `decrypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/ofb.py:93`

Docstring: **Present**

### `cryptocore.modes.ofb.encrypt_ofb`

Signature: `encrypt_ofb(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/ofb.py:68`

Docstring: **Present**

### `cryptocore.modes.ofb.process_ofb`

Signature: `process_ofb(data: bytes, key: bytes, iv: bytes) -> bytes`

Source: `src/cryptocore/modes/ofb.py:13`

Docstring: **Present**

### `cryptocore.nonce_registry.register_nonce`

Signature: `register_nonce(key: bytes, nonce: bytes, mode: str, database: str | Path | None=None) -> None`

Source: `src/cryptocore/nonce_registry.py:12`

Docstring: **Present**

### `cryptocore.streaming.decrypt_file`

Signature: `decrypt_file(source_path: str | Path, destination: str | Path, key: bytes, mode: str, aad: bytes | BinaryIO=b'', iv: bytes | None=None, nonce: bytes | None=None) -> None`

Source: `src/cryptocore/streaming.py:161`

Docstring: **Present**

### `cryptocore.streaming.encrypt_file`

Signature: `encrypt_file(source_path: str | Path, destination: str | Path, key: bytes, mode: str, aad: bytes | BinaryIO=b'') -> None`

Source: `src/cryptocore/streaming.py:104`

Docstring: **Present**

### `hash.sha256.SHA256`

Signature: `class SHA256`

Source: `src/hash/sha256.py:61`

Docstring: **Present**

### `hash.sha256.SHA256.__init__`

Signature: `__init__(self) -> None`

Source: `src/hash/sha256.py:70`

Docstring: **Present**

### `hash.sha256.SHA256.copy`

Signature: `copy(self) -> 'SHA256'`

Source: `src/hash/sha256.py:89`

Docstring: **Present**

### `hash.sha256.SHA256.digest`

Signature: `digest(self) -> bytes`

Source: `src/hash/sha256.py:426`

Docstring: **Present**

### `hash.sha256.SHA256.hash`

Signature: `hash(cls, data: bytes | bytearray | memoryview) -> str`

Source: `src/hash/sha256.py:465`

Docstring: **Present**

### `hash.sha256.SHA256.hexdigest`

Signature: `hexdigest(self) -> str`

Source: `src/hash/sha256.py:449`

Docstring: **Present**

### `hash.sha256.SHA256.update`

Signature: `update(self, data: bytes | bytearray | memoryview) -> SHA256`

Source: `src/hash/sha256.py:116`

Docstring: **Present**

### `hash.sha3_256.SHA3_256`

Signature: `class SHA3_256`

Source: `src/hash/sha3_256.py:151`

Docstring: **Present**

### `hash.sha3_256.SHA3_256.__init__`

Signature: `__init__(self) -> None`

Source: `src/hash/sha3_256.py:160`

Docstring: **Present**

### `hash.sha3_256.SHA3_256.copy`

Signature: `copy(self) -> 'SHA3_256'`

Source: `src/hash/sha3_256.py:174`

Docstring: **Present**

### `hash.sha3_256.SHA3_256.digest`

Signature: `digest(self) -> bytes`

Source: `src/hash/sha3_256.py:338`

Docstring: **Present**

### `hash.sha3_256.SHA3_256.hash`

Signature: `hash(cls, data: bytes | bytearray | memoryview) -> str`

Source: `src/hash/sha3_256.py:381`

Docstring: **Present**

### `hash.sha3_256.SHA3_256.hexdigest`

Signature: `hexdigest(self) -> str`

Source: `src/hash/sha3_256.py:365`

Docstring: **Present**

### `hash.sha3_256.SHA3_256.update`

Signature: `update(self, data: bytes | bytearray | memoryview) -> 'SHA3_256'`

Source: `src/hash/sha3_256.py:197`

Docstring: **Present**

### `kdf.hkdf.derive_key`

Signature: `derive_key(master_key: bytes, context: str, length: int=32) -> bytes`

Source: `src/kdf/hkdf.py:10`

Docstring: **Present**

### `kdf.pbkdf2.pbkdf2_hmac_sha256`

Signature: `pbkdf2_hmac_sha256(password: bytes | bytearray | str, salt: bytes, iterations: int, dklen: int) -> bytes`

Source: `src/kdf/pbkdf2.py:53`

Docstring: **Present**

### `mac.hmac.HMAC`

Signature: `class HMAC`

Source: `src/mac/hmac.py:11`

Docstring: **Present**

### `mac.hmac.HMAC.__init__`

Signature: `__init__(self, key: bytes | bytearray | memoryview) -> None`

Source: `src/mac/hmac.py:20`

Docstring: **Present**

### `mac.hmac.HMAC.compute`

Signature: `compute(cls, key: bytes | bytearray | memoryview, data: bytes | bytearray | memoryview) -> str`

Source: `src/mac/hmac.py:218`

Docstring: **Present**

### `mac.hmac.HMAC.copy`

Signature: `copy(self) -> 'HMAC'`

Source: `src/mac/hmac.py:111`

Docstring: **Present**

### `mac.hmac.HMAC.digest`

Signature: `digest(self) -> bytes`

Source: `src/mac/hmac.py:171`

Docstring: **Present**

### `mac.hmac.HMAC.hexdigest`

Signature: `hexdigest(self) -> str`

Source: `src/mac/hmac.py:202`

Docstring: **Present**

### `mac.hmac.HMAC.update`

Signature: `update(self, data: bytes | bytearray | memoryview) -> 'HMAC'`

Source: `src/mac/hmac.py:136`

Docstring: **Present**

### `modes.gcm.AuthenticationError`

Signature: `class AuthenticationError`

Source: `src/modes/gcm.py:17`

Docstring: **Present**

### `modes.gcm.GCM`

Signature: `class GCM`

Source: `src/modes/gcm.py:114`

Docstring: **Present**

### `modes.gcm.GCM.__init__`

Signature: `__init__(self, key: bytes, nonce: bytes | None=None) -> None`

Source: `src/modes/gcm.py:123`

Docstring: **Present**

### `modes.gcm.GCM.decrypt`

Signature: `decrypt(self, data: bytes, aad: bytes | BinaryIO=b'', includes_nonce: bool=True) -> bytes`

Source: `src/modes/gcm.py:394`

Docstring: **Present**

### `modes.gcm.GCM.encrypt`

Signature: `encrypt(self, plaintext: bytes, aad: bytes | BinaryIO=b'') -> bytes`

Source: `src/modes/gcm.py:350`

Docstring: **Present**
