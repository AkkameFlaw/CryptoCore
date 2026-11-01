# CryptoCore — тестовые векторы PBKDF2-HMAC-SHA256

## Назначение

В Sprint 7 реализован алгоритм PBKDF2-HMAC-SHA256 с использованием собственной реализации HMAC-SHA256 из Sprint 5.

Для проверки корректности используются известные значения PBKDF2-HMAC-SHA256 и независимая реализация `hashlib.pbkdf2_hmac()` из стандартной библиотеки Python.

## Уточнение по RFC 6070

RFC 6070 содержит тестовые векторы для **PBKDF2-HMAC-SHA1**, а не PBKDF2-HMAC-SHA256.

Поэтому значения:

- `0c60c80f961f0e71f3a9b524af6012062fe037a6`
- `ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957`

не являются ожидаемыми результатами нашей реализации с SHA-256.

В Sprint 7 для тех же пароля и salt применяются проверенные значения PBKDF2-HMAC-SHA256.

## Тестовые векторы SHA-256

Параметры для всех трёх случаев:

```text
Password: password
Salt: salt
Derived key length: 32 bytes
PRF: HMAC-SHA256
```

| Тест | Итерации | Ожидаемый ключ (HEX) |
|---|---:|---|
| 1 | 1 | `120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b` |
| 2 | 2 | `ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43` |
| 3 | 4096 | `c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a` |

Эти значения проверяются в `tests/test_pbkdf2_vectors.py`.

## Независимое подтверждение

Результаты сравниваются с:

```python
hashlib.pbkdf2_hmac(
    "sha256",
    password,
    salt,
    iterations,
    dklen=32,
)
```

`hashlib` используется только для тестирования, а не в реализации PBKDF2.

## Проверка с OpenSSL

Дополнительно выполнена независимая проверка с OpenSSL 3.6.4.

Параметры:

```text
Password: password
Salt (HEX): 73616c74
Iterations: 2
Key length: 32 bytes
Digest: SHA256
```

Результат CryptoCore:

```text
ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
```

Результат OpenSSL:

```text
ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
```

Совпадение: **True**.

## Вывод

Таким образом, реализация Sprint 7 проверяется по значениям, соответствующим именно PBKDF2-HMAC-SHA256. Векторы RFC 6070 для HMAC-SHA1 не используются ошибочно в качестве ожидаемых результатов HMAC-SHA256.