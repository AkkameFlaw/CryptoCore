# Sprint 8 — матрица требований и готовности

Матрица основана на техническом задании Sprint 8 и исходном ZIP. **Статус «нужен повторный запуск» означает, что новый ZIP не был полностью проверен в пользовательской среде.**

| Группа | Реализация | Доказательство / ограничение |
|---|---|---|
| STR-1 | Предыдущие модули сохранены | AST-проверка показала отсутствие изменений логики в 24 файлах `src` (кроме версии) |
| STR-2 | `docs/API.md`, `USERGUIDE.md`, `DEVELOPMENT.md`, `examples` | Файлы присутствуют |
| STR-3 | `tests/unit`, `integration`, `vectors`, `run_tests.py` | Тесты расположены также и в корне `tests` ради совместимости |
| STR-4 | Docstrings модулей, классов и функций | AST-аудит: 84 публичных определений, пропущено 0 docstrings; 107 определений всего, пропущено 0 |
| TEST-1 | Ветвевое покрытие 91.63% по отчёту пользователя | Это не полное покрытие всех путей; отдельные модули ниже 90% |
| TEST-2 | Векторы AES, GCM, SHA, HMAC, PBKDF2-HMAC-SHA256 | `tests/vectors`, `tests/test_gcm.py`, `tests/test_sha*.py`, `tests/test_hmac_vectors.py`, `tests/test_pbkdf2_vectors.py`; RFC 6070 относится к SHA-1 |
| TEST-3 | End-to-end режимов AES, hash, HMAC, derive | `tests/integration/test_sprint8_cli.py` — в пользовательской среде пройден |
| TEST-4 | Негативные тесты | Уже есть для AEAD, ключей, AAD и отсутствующего файла; права доступа зависят от ОС |
| TEST-5 | Benchmarks AES, SHA, PBKDF2 | `scripts/benchmark_aes.py`, `benchmark_hash.py`, `benchmark_pbkdf2.py`; AES результаты ещё не измерены |
| TEST-6 | OpenSSL совместимость | Создан `tests/integration/test_openssl_compat.py` для ECB, CBC, CFB, OFB, CTR. Нужен повторный запуск при наличии OpenSSL; GCM проверяется с PyCryptodome |
| TEST-7 | Безопасность памяти | Проверяется очистка изменяемых буферов; тест обработки файла >1 ГБ не выполнен, возможен высокий расход RAM в AES CLI |
| TEST-8 | Единая команда | `python tests/run_tests.py --enforce-coverage` |
| DOC-1..5 | Документация публичных API и схема зависимостей | `docs/API.md`; указана фактическая структура без несуществующего `cryptocore.aes` или CMAC |
| UG-1..7 | Установка Windows/Linux/macOS, сценарии и справка | `docs/USERGUIDE.md` |
| QA-1..2 | Статический аудит ограничений реализации | `docs/SECURITY_AUDIT.md`; не заменяет полноценный security audit |
| QA-3 | Runtime/dev версии зависимостей | `pyproject.toml` и `requirements.txt` |
| QA-4..6 | История изменений и политики | `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` |

## Финальные команды на Windows

```powershell
pip install -e ".[dev]"
python scripts\audit_public_api.py
pytest tests\integration\test_openssl_compat.py -v
python tests\run_tests.py --enforce-coverage
python docs\examples\demo_api.py
python scripts\benchmark_aes.py --size-mb 1
python -c "from cryptocore import __version__; print(__version__)"
```

Ожидаемая версия: `0.8.0`. При наличии OpenSSL в `PATH` или `C:\msys64\ucrt64\bin\openssl.exe` пять дополнительных совместимых режимов должны быть протестированы. **Не заявляйте, что эти 5 новых тестов прошли, до получения реального вывода.**
