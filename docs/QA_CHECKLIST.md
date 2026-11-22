# CryptoCore Sprint 8 — матрица приёмки, состояние 0.8.2

| Требование | Реализация | Подтверждение |
|---|---|---|
| Сохранение функциональности Sprint 1–7 | Все ранее реализованные модули и форматы сохранены | Полный регрессионный набор `tests/` должен пройти на целевой машине |
| Документация публичного API | `docs/API.md` и генерируемый `docs/API_INVENTORY.md` | `python scripts/audit_public_api.py` |
| Руководство пользователя и разработчика | `docs/USERGUIDE.md`, `docs/DEVELOPMENT.md` | Ревизия примеров CLI |
| Единый запуск тестов | `tests/run_tests.py --enforce-coverage` | Порог 90.01%, с измерением ветвей |
| Криптографические векторы | Тесты AES, SHA, HMAC, PBKDF2 и GCM | `tests/vectors`, `tests/test_gcm.py`, `tests/test_hmac_vectors.py` |
| Файловые AEAD и AAD | Потоковый GCM/EtM, поддержка `--aad-file` | `tests/integration/test_security_hardening.py` |
| Повтор nonce в CLI и библиотеке | Общий SQLite-реестр высокоуровневых путей | `tests/integration/test_security_followup_v082.py` |
| Нативный GHASH на рабочем пути GCM | `modes.GCM` и `cryptocore.streaming` используют PyCryptodome | Проверка NIST-векторов и сравнение с PyCryptodome |
| PBKDF2 и секреты в stdout/argv | Пределы, ввод без эха, явный opt-in | `tests/test_derive_cli.py`, security integration |
| Бинарные файлы большого размера | Потоковый CLI; ручной тест 1.05 ГиБ предусмотрен | `scripts/verify_large_stream.py` — ручной запуск пока не подтверждён |
| Проверка совместимости | OpenSSL для стандартных AES-режимов | `tests/integration/test_openssl_compat.py`, если доступен OpenSSL |
| Документирование известных ограничений | `SECURITY.md`, `docs/SECURITY_AUDIT.md`, `docs/SECURITY_REVIEW_2026.md` | Ручная ревизия |

**Последние подтверждённые Windows-значения относятся к v0.8.1:** `409 passed`, `94.69%`. При публикации версии 0.8.2 их нельзя выдавать за результаты новой сборки; обновить после повторного запуска.


**Предварительный прогон 0.8.2 (Linux, Python 3.13, тестовый совместимый адаптер AES на основе `cryptography`):** 422 теста успешно пройдены, 95,40% общего покрытия строк и ветвей. Это не заменяет полный запуск с настоящим PyCryptodome на Windows; адаптер не входит в поставку.
