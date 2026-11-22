# Changelog — CryptoCore

## [0.8.2] — Extended security follow-up (2026-11-22)

- Replaced the remaining in-library table-based Python GHASH with PyCryptodome AES-GCM. Retained the original GHASH code solely as a teaching reference outside the runtime package.
- Extended persistent nonce/IV reservation to high-level in-memory GCM and EtM operations and legacy `cli.encrypt_data` for IV-based modes, consistent with the streaming CLI.
- Indexed EtM reservations using the derived AES encryption key; both the library and streaming paths follow the same rule.
- Made `derive --output` create private key files exclusively, rejecting overwrite of an existing secret file.
- Added isolated nonce registries for test cases and regressions for cross-API reuse, concurrency, native-GCM authentication and fail-closed behavior.
- Updated README, SECURITY, API, user/developer guides, audit and QA documents, including documented residual risks.
- Historical Windows verification for v0.8.1: 409 tests passed, 94.69% coverage. Preliminary v0.8.2 check (Linux, compatibility AES adapter): 422 passed, 95.40% branch-aware coverage; native Windows/PyCryptodome verification remains required.

## 0.8.1 — Security review remediation (2026-11-18)

- Added persistent key/nonce registry for CLI encryption, including fail-closed collision detection.
- Added bounded-memory file processing for all AES modes with atomic output replacement.
- CLI GCM now uses PyCryptodome native AES-GCM; own GHASH remains an educational non-constant-time implementation.
- Added opt-in gates for argv password and stdout secret material, plus `--password-prompt` and `--key-file`.
- Added upper bounds on PBKDF2 iteration count and explicit slow-KDF consent.
- Enabled streaming `--aad-file` for EtM.
- Added security regression tests and explicit risk documentation.

## [0.8.0] — Sprint 8, подготовка к демонстрации

- Добавлены документация API, руководство пользователя, руководство разработчика и примеры.
- Для исходных модулей и доступных функций подготовлены docstrings без изменения вычислительной логики.
- Добавлены воспроизводимые команды аудита, измерения покрытия и тесты совместимости AES с OpenSSL (при его наличии).
- Созданы SECURITY.md, CONTRIBUTING.md, docs/SECURITY_AUDIT.md и CHANGELOG.md.
- Зафиксированы версии зависимостей пользователя; сохранены результаты 323 прошедших тестов и 91.63% ветвевого покрытия из его среды.

## [0.7.0] — Sprint 7
- PBKDF2-HMAC-SHA256; CLI derive; генерация salt, иерархия HMAC-ключей, проверки OpenSSL.
- Ограничение dklen до 65536 байт и best-effort zeroization CLI.
- Производительность для 10k, 100k, 1M итераций.

## [0.6.0] — Sprint 6
- AES-GCM, GHASH, AAD, Encrypt-then-MAC; отрицательные и NIST-тесты.

## [0.5.0] — Sprint 5
- HMAC-SHA256 на собственной SHA-256, RFC 4231, команда dgst --hmac.

## [0.4.0] — Sprint 4
- SHA-256, SHA3-256, потоковое хеширование и benchmark.

## [0.3.0] — Sprint 3
- CSPRNG на os.urandom, статистические проверки.

## [0.2.0] — Sprint 2
- CBC, CFB, OFB, CTR.

## [0.1.0] — Sprint 1
- AES-128 ECB, PKCS#7 и файловый CLI.
