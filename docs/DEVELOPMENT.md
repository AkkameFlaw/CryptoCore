# CryptoCore — руководство разработчика

## Среда

Python ≥3.10, верифицированная пользователем среда: Windows 10, Python 3.14.0, PyCryptodome 3.23.0, pytest 8.4.2, pytest-cov 7.1.0, OpenSSL 3.6.4. Конкретные версии для воспроизведения указаны в pyproject.toml.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python tests\run_tests.py --enforce-coverage
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python tests/run_tests.py --coverage
```

## Архитектура

Пакеты в `src`: `cryptocore` (CLI, I/O, классические AES-режимы), `hash` (SHA-256/SHA3-256), `mac` (HMAC), `kdf` (PBKDF2/контекстное разделение), `modes` (GCM), `aead` (EtM). Внешний блочный AES предоставляется PyCryptodome. Схему зависимостей см. в [API.md](API.md).

Упаковка использует `setuptools` с `package-dir = {"" = "src"}`; не переносите папки в `cryptocore.*` без изменения импортов и тестов. Изменения файлового формата должны сопровождаться тестами обратной совместимости.

## Проверка

```powershell
pytest -q
python tests\run_tests.py --coverage
python tests\run_tests.py --enforce-coverage
python scripts\audit_public_api.py
```

`--cov-branch` измеряет покрытие строк/ветвей, **не** все возможные логические пути. Целевой порог >90% общего покрытия. После изменения исходников проверяйте [API_INVENTORY.md](API_INVENTORY.md).

Историческая проверка пользователя для **0.8.1** дала **409 пройденных тестов и 94,69% покрытия**. Новая сборка **0.8.2** требует отдельного полного прогона с установленным PyCryptodome.

Структура тестов: `tests/unit`, `tests/integration`, `tests/vectors` и ранее существующие `tests/test_*.py`. Сохранена совместимость со старым расположением. `tests/run_tests.py` запускает весь набор. Для локальных запусков с небольшим временем используйте `pytest tests/unit tests/integration -q`.

## Тестовые векторы

AES SP 800-38A, GCM SP 800-38D, SHA FIPS 180-4/202, HMAC RFC 4231, PBKDF2-HMAC-SHA256 — корректные SHA-256-векторы, **не** RFC 6070 SHA-1. См. [vectors.md](vectors.md). OpenSSL используется как внешний эталон для классических AES-режимов, PyCryptodome — для GCM.

## Производительность

```powershell
python scripts\benchmark_hash.py
python scripts\benchmark_pbkdf2.py --iterations 10000
python scripts\benchmark_pbkdf2.py --iterations 100000
python scripts\benchmark_pbkdf2.py --iterations 1000000
python scripts\benchmark_aes.py --size-mb 1
```

PBKDF2 1M в пользовательской среде — 772.445409 с, повторно по умолчанию в pytest не запускается. Не добавляйте бенчмарки в CI без временных ограничений.

## Совместимость и проверка безопасности

Проверка OpenSSL (требует наличия OpenSSL в PATH или C:\msys64\ucrt64\bin\openssl.exe):

```powershell
pytest tests/integration/test_openssl_compat.py -v
```

Проверки с файлами больше 1 ГиБ в пользовательской среде не подтверждены и не включены в обычный CI. Для основного AES-файла используется `cryptocore.streaming` (64 КиБ), для in-memory API загрузка в память остаётся частью контракта. Не храните реальные ключи в тестах.

## Сборка и выпуск

```powershell
python -m compileall -q src
python -m pip install -e ".[dev]"
pytest -q
python -c "from cryptocore import __version__; print(__version__)"
```

Сначала убедитесь, что версия в `pyproject.toml` и `src/cryptocore/__init__.py` согласована, затем сделайте коммит и Push origin в GitHub Desktop. Изменения в docstrings не должны влиять на криптографические выходы; регрессионные тесты обязательны.


## Задачи для сопровождающего v0.8.2

- Публичные `GCM.encrypt`, `EncryptThenMAC.encrypt`, `cli.encrypt_data` используют локальный реестр nonce. Тесты выполняются с **отдельной базой для каждого test case** из `tests/conftest.py`, чтобы NIST-векторы с фиксированными nonce не загрязняли рабочую БД. Не отключайте проверку nonce в продукционном пути ради детерминированных тестов.
- Рабочий класс `modes.GCM` использует PyCryptodome. Перенесённый `docs/examples/ghash_reference.py` — только учебный фрагмент, не импортируйте его в `src`.
- Сохраняйте совместимость форматов `IV || ciphertext`, `nonce || ciphertext || tag`. Новые файловые операции проводите через потоковый API и проверяйте атомарную публикацию результата.
- После изменения исходников запускайте `python scripts/audit_public_api.py` и `python tests/run_tests.py --enforce-coverage`; отдельные тесты: `pytest tests/integration/test_security_followup_v082.py -v`. Не копируйте старые проценты покрытия 0.8.1 как новые.
- Для проверки >1 ГиБ отдельный сценарий `python scripts/verify_large_stream.py --gib 1.05 --yes` требует свободный диск и не относится к быстрому CI.
