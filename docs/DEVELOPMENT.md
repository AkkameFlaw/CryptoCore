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

В пользовательской среде до документирования были получены **323 passed** и **91.63% общего покрытия строк/ветвей**, включая тесты интеграции. Повторное тестирование на обновлённой сборке требуется.

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

Проверки с большими файлами (>1ГБ) необязательны и не проведены в этом пакете. Не включайте в быстрый CI. Для хеширования допустима потоковая обработка; AES CLI целиком читает входной файл, что может быть проблемой для памяти. Не храните реальные ключи в тестах.

## Сборка и выпуск

```powershell
python -m compileall -q src
python -m pip install -e ".[dev]"
pytest -q
python -c "from cryptocore import __version__; print(__version__)"
```

Сначала убедитесь, что версия в `pyproject.toml` и `src/cryptocore/__init__.py` согласована, затем сделайте коммит и Push origin в GitHub Desktop. Изменения в docstrings не должны влиять на криптографические выходы; регрессионные тесты обязательны.
