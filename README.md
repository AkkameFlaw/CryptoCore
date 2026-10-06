# CryptoCore

CryptoCore — консольный инструмент для работы с криптографическими алгоритмами.

Проект развивается по спринтам. Каждый следующий спринт расширяет существующую реализацию и сохраняет функциональность предыдущих этапов.

Текущая версия проекта:

```text
0.5.0
```

# Реализованные возможности

## Sprint 1

В первом спринте мы реализовали:

- AES-128;
- режим ECB;
- PKCS#7 padding;
- CLI-интерфейс;
- работу с текстовыми и бинарными файлами;
- проверку аргументов командной строки;
- обработку файловых ошибок;
- автоматические тесты;
- полный цикл encrypt -> decrypt;
- проверку совместимости с OpenSSL.

## Sprint 2

Во втором спринте мы добавили:

- CBC;
- CFB;
- OFB;
- CTR;
- автоматическую генерацию IV;
- хранение IV в начале зашифрованного файла;
- передачу IV через CLI при расшифровании;
- проверку корректности IV;
- автоматические тесты новых режимов;
- проверку совместимости с внешними реализациями.

## Sprint 3

В третьем спринте мы добавили:

- отдельный модуль CSPRNG;
- функцию `generate_random_bytes(num_bytes)`;
- использование `os.urandom()`;
- автоматическую генерацию AES-128 ключа;
- вывод созданного ключа в терминал;
- обязательный ключ при расшифровании;
- генерацию IV через общий CSPRNG;
- предупреждение о потенциально слабых ключах;
- тест генерации 1000 уникальных ключей;
- базовую статистическую проверку распределения битов;
- генератор данных для NIST STS;
- проверку CSPRNG через NIST Statistical Test Suite.

## Sprint 4

В четвёртом спринте мы добавили:

- отдельную команду `dgst`;
- SHA-256, реализованный с нуля;
- SHA3-256, реализованный с нуля;
- отдельный каталог `src/hash/`;
- потоковое хеширование файлов;
- обработку пустых файлов;
- поддержку входных данных произвольной длины;
- запись результата в stdout;
- запись результата через `--output`;
- известные тестовые векторы;
- проверку совместимости с системными реализациями;
- тест лавинного эффекта;
- сценарий проверки больших файлов;
- измерение производительности собственных реализаций.

## Sprint 5

В пятом спринте мы добавили:

- HMAC-SHA256;
- собственную реализацию HMAC по RFC 2104;
- использование собственной SHA-256 из Sprint 4;
- отдельный каталог `src/mac/`;
- флаг `--hmac` для команды `dgst`;
- HEX-ключ произвольной длины через `--key`;
- проверку HMAC через `--verify`;
- запись HMAC через `--output`;
- потоковую обработку файлов;
- тестовые векторы RFC 4231;
- проверку ключей разных размеров;
- обнаружение изменения файла;
- обнаружение использования неправильного ключа;
- обработку пустого файла;
- отдельный сценарий проверки HMAC больших файлов.

# Требования

Для запуска проекта понадобятся:

- Python 3.10 или новее;
- PyCryptodome;
- pytest.

Для дополнительных проверок использовались:

- OpenSSL;
- `sha256sum`;
- NIST Statistical Test Suite.

# Установка

Создадим виртуальное окружение:

```powershell
python -m venv .venv
```

Активируем его:

```powershell
.\.venv\Scripts\Activate.ps1
```

Обновим pip:

```powershell
python -m pip install --upgrade pip
```

Установим проект вместе с зависимостями для разработки:

```powershell
pip install -e ".[dev]"
```

# Проверка установки

Проверим CLI:

```powershell
cryptocore --help
```

Также программу можно запустить через Python:

```powershell
python -m cryptocore --help
```

# AES-128

CryptoCore поддерживает AES-128.

Если ключ задаётся вручную, он передаётся как HEX-строка длиной 32 символа:

```text
000102030405060708090a0b0c0d0e0f
```

Поддерживаются режимы:

```text
ecb
cbc
cfb
ofb
ctr
```

# Формат команды AES

```text
cryptocore --algorithm aes --mode MODE --encrypt|--decrypt [--key KEY] --input INPUT [--output OUTPUT] [--iv IV]
```

# Sprint 1 — ECB

Шифрование:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

ECB использует PKCS#7 padding.

# Sprint 2 — дополнительные режимы AES

## CBC

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cbc.bin
```

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

CBC использует PKCS#7 padding.

## CFB

```powershell
cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cfb.bin
```

CFB не использует padding.

## OFB

```powershell
cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ofb.bin
```

OFB не использует padding.

## CTR

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ctr.bin
```

CTR не использует padding.

# Работа с IV

Для CBC, CFB, OFB и CTR используется IV длиной 16 байт.

При шифровании IV создаётся автоматически через CSPRNG.

Формат зашифрованного файла:

```text
<16-byte IV><ciphertext>
```

При обычном расшифровании CryptoCore считывает первые 16 байт файла как IV.

IV также можно передать вручную:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input ciphertext.bin --output decrypted.txt
```

# Sprint 3 — CSPRNG

Реализация находится:

```text
src/cryptocore/csprng.py
```

Основная функция:

```python
generate_random_bytes(num_bytes)
```

Для генерации случайных данных используется:

```python
os.urandom()
```

`os.urandom()` получает случайные данные из криптографически стойкого системного источника случайности и подходит для генерации криптографического материала.

Модуль `random` для ключей и IV не используется.

# Автоматическая генерация AES-ключа

При шифровании параметр `--key` необязателен:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

CryptoCore создаёт случайный AES-128 ключ:

```text
[INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```

Сгенерированный ключ не записывается в ciphertext.

Для последующего расшифрования его необходимо сохранить отдельно.

При расшифровании ключ обязателен.

# NIST Statistical Test Suite

CSPRNG дополнительно проверялся через NIST Statistical Test Suite.

Использовались:

```text
100 последовательностей
1 000 000 бит в каждой последовательности
Binary input
Все 15 тестов NIST STS
```

Полный отчёт находится:

```text
docs/nist_final_report.txt
```

# Sprint 4 — хеширование

# Структура хеш-функций

Реализации находятся:

```text
src/hash/
├── __init__.py
├── sha256.py
└── sha3_256.py
```

# Команда dgst

Для вычисления message digest используется:

```text
cryptocore dgst
```

Формат:

```text
cryptocore dgst --algorithm ALGORITHM --input INPUT_FILE [--output OUTPUT_FILE]
```

Поддерживаются:

```text
sha256
sha3-256
```

Например:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
```

Формат результата:

```text
HASH_VALUE  INPUT_FILE_PATH
```

# SHA-256

Реализация:

```text
src/hash/sha256.py
```

SHA-256 реализован без использования `hashlib`.

Реализация включает:

- обработку блоков по 512 бит;
- восемь 32-битных слов состояния;
- 64 раунда;
- раундовые константы;
- расширение расписания сообщения;
- операции Choice и Majority;
- циклические сдвиги;
- SHA-256 padding;
- добавление 64-битной длины сообщения;
- `update()`;
- `digest()`;
- `hexdigest()`.

Результат имеет длину 256 бит и представляется 64 шестнадцатеричными символами в нижнем регистре.

# SHA3-256

Реализация:

```text
src/hash/sha3_256.py
```

SHA3-256 также реализован без использования `hashlib`.

Реализация включает:

- губчатую конструкцию;
- состояние Keccak-f[1600];
- 24 раунда;
- Theta;
- Rho;
- Pi;
- Chi;
- Iota;
- domain separation;
- padding;
- `update()`;
- `digest()`;
- `hexdigest()`.

Для SHA3-256 используется rate:

```text
1088 бит
136 байт
```

# Свойства безопасности хеш-функций

SHA-256 и SHA3-256 формируют хеш длиной 256 бит.

Для идеальной криптографической хеш-функции с выходом 256 бит сложность поиска прообраза составляет порядка:

```text
2^256
```

а сложность поиска коллизии по принципу парадокса дней рождения — порядка:

```text
2^128
```

SHA-256 использует конструкцию Merkle-Damgard.

SHA3-256 основан на Keccak и использует губчатую конструкцию.

Даже небольшое изменение входных данных приводит к значительному изменению результата, что дополнительно проверяется тестом лавинного эффекта.

# Потоковая обработка файлов

При вычислении хеша файл не загружается полностью в оперативную память.

Файл читается блоками:

```text
8192 байт
```

Каждый блок передаётся в:

```python
update()
```

Файловая логика находится:

```text
src/cryptocore/digest.py
```

# Пустой ввод

SHA-256 пустого сообщения:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

SHA3-256 пустого сообщения:

```text
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
```

# Известные тестовые векторы

Для SHA-256 проверяются:

```text
""
"abc"
abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq
1 000 000 символов "a"
```

Для SHA3-256 проверяются:

```text
""
"abc"
"The quick brown fox jumps over the lazy dog"
1 000 000 символов "a"
```

Модуль `hashlib` используется только в тестах как независимая эталонная реализация.

# Проверка совместимости хеширования

SHA-256 проверялся через:

```bash
sha256sum hash_test.txt
```

и:

```powershell
cryptocore dgst --algorithm sha256 --input hash_test.txt
```

Полученные хеши совпали.

SHA3-256 проверялся через:

```bash
openssl dgst -sha3-256 hash_test.txt
```

и:

```powershell
cryptocore dgst --algorithm sha3-256 --input hash_test.txt
```

Полученные хеши также совпали.

# Производительность Sprint 4

Для измерения производительности используется:

```text
scripts/benchmark_hash.py
```

Измерения проводились на:

```text
Python 3.14.0
Windows 10
```

Использовались файлы:

```text
1 МБ
5 МБ
10 МБ
```

Результаты:

| Размер | Алгоритм | CryptoCore, с | Системная утилита | Система, с | Замедление | Совпадение |
| ---: | --- | ---: | --- | ---: | ---: | --- |
| 1 МБ | SHA-256 | 6.082333 | sha256sum | 0.342494 | 17.76x | True |
| 1 МБ | SHA3-256 | 7.778663 | OpenSSL | 0.517732 | 15.02x | True |
| 5 МБ | SHA-256 | 33.321969 | sha256sum | 0.171867 | 193.88x | True |
| 5 МБ | SHA3-256 | 40.372300 | OpenSSL | 0.039735 | 1016.05x | True |
| 10 МБ | SHA-256 | 62.086354 | sha256sum | 0.227347 | 273.09x | True |
| 10 МБ | SHA3-256 | 79.184037 | OpenSSL | 0.057318 | 1381.48x | True |

Во всех случаях:

```text
Совпадение = True
```

Подробный отчёт:

```text
docs/sprint4_performance.md
```

# Sprint 5 — HMAC

# Структура MAC

Реализация MAC находится:

```text
src/mac/
├── __init__.py
└── hmac.py
```

HMAC реализован с нуля и использует собственную реализацию SHA-256 из:

```text
src/hash/sha256.py
```

Стандартный модуль Python `hmac` не используется внутри реализации CryptoCore.

Он используется только в автоматических тестах как независимая эталонная реализация.

# Конструкция HMAC

В проекте реализована конструкция:

```text
HMAC(K, m) = H((K XOR opad) || H((K XOR ipad) || m))
```

где:

```text
H     = SHA-256
ipad  = 0x36
opad  = 0x5c
```

Размер блока SHA-256:

```text
64 байта
```

Если ключ длиннее 64 байт, он сначала хешируется через SHA-256.

Если ключ короче 64 байт, он дополняется нулевыми байтами до размера блока.

Ключ длиной ровно 64 байта используется непосредственно.

HMAC поддерживает ключи произвольной длины.

# Свойства HMAC

HMAC используется для проверки подлинности и целостности данных.

В отличие от обычного хеша, результат HMAC зависит не только от сообщения, но и от секретного ключа.

Это позволяет обнаруживать:

- изменение содержимого файла;
- использование неправильного ключа;
- попытку подмены данных без знания секретного ключа.

HMAC не шифрует данные и не обеспечивает конфиденциальность содержимого.

Для сравнения вычисленного и ожидаемого HMAC при проверке используется:

```python
secrets.compare_digest()
```

# Генерация HMAC

Для HMAC команда `dgst` расширена флагом:

```text
--hmac
```

Формат:

```text
cryptocore dgst --algorithm sha256 --hmac --key KEY --input INPUT_FILE
```

Ключ передаётся как шестнадцатеричная строка.

Например:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
```

Формат результата:

```text
HMAC_VALUE INPUT_FILE_PATH
```

# RFC 4231

Реализация проверяется тестовыми векторами RFC 4231.

Например, для:

```text
Message: Hi There
Key:     20 байт 0x0b
```

создадим файл:

```powershell
Set-Content -NoNewline -Path sprint5.txt -Value "Hi There"
```

Создадим ключ:

```powershell
$key = "0b" * 20
```

Запустим:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt
```

Ожидаемый HMAC:

```text
b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
```

Автоматические тесты содержат тестовые случаи 1–4 RFC 4231.

# Запись HMAC в файл

Можно использовать `--output`:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --output sprint5.hmac
```

Файл содержит:

```text
HMAC_VALUE INPUT_FILE_PATH
```

# Проверка HMAC

Для проверки используется:

```text
--verify
```

Например:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --verify sprint5.hmac
```

При успешной проверке:

```text
[OK] HMAC verification successful
```

Код возврата:

```text
0
```

Если содержимое файла или ключ не совпадают:

```text
[ERROR] HMAC verification failed
```

Код возврата:

```text
1
```

# Проверка подмены файла

Сначала создадим HMAC:

```powershell
Set-Content -NoNewline -Path sprint5.txt -Value "Hi There"
```

```powershell
$key = "0b" * 20
```

```powershell
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --output sprint5.hmac
```

Изменим файл:

```powershell
Set-Content -NoNewline -Path sprint5.txt -Value "Hi There!"
```

Проверим:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --verify sprint5.hmac
```

Результат:

```text
[ERROR] HMAC verification failed
```

Таким образом, изменение содержимого файла обнаруживается.

# Проверка неправильного ключа

Автоматические тесты:

1. создают HMAC с одним ключом;
2. выполняют проверку с другим ключом;
3. ожидают завершение с ненулевым кодом.

Это подтверждает, что корректный HMAC невозможно проверить с другим ключом.

# Размеры ключей

Автоматически проверяются ключи размером:

```text
16 байт
64 байта
100 байт
```

Таким образом проверяются:

- ключ короче блока SHA-256;
- ключ, равный размеру блока;
- ключ длиннее блока.

# Пустой файл

HMAC корректно вычисляется и для файла нулевой длины.

Этот случай проверяется автоматическими тестами.

# Потоковая обработка HMAC

Файл для HMAC не загружается полностью в память.

В:

```text
src/cryptocore/digest.py
```

он читается частями:

```text
8192 байт
```

Каждый блок последовательно передаётся в:

```python
HMAC.update()
```

Поэтому объём оперативной памяти, используемый самой HMAC-обработкой файла, практически не зависит от общего размера входного файла.

# Проверка больших файлов HMAC

Для отдельной проверки создан:

```text
scripts/test_large_hmac.py
```

Например:

```powershell
python scripts\test_large_hmac.py --size-mb 16
```

Скрипт:

1. создаёт бинарный файл заданного размера;
2. вычисляет эталонный HMAC-SHA256 через стандартные `hmac` и `hashlib`;
3. вычисляет HMAC через CryptoCore;
4. сравнивает результаты.

Успешный результат:

```text
Expected: <HMAC>
Actual:   <HMAC>
Match:    True
```

Размер файла можно изменять параметром:

```text
--size-mb
```

Это позволяет отдельно выполнять длительные проверки потоковой обработки без включения их в обычный запуск `pytest`.

# AES-CMAC

AES-CMAC в Sprint 5 не реализован.

В техническом задании AES-CMAC является бонусной функциональностью и не относится к обязательной реализации HMAC-SHA256.

# Автоматические тесты

Для запуска всех тестов:

```powershell
pytest -q
```

Проверяются:

- AES-128;
- ECB;
- CBC;
- CFB;
- OFB;
- CTR;
- PKCS#7;
- ключи AES;
- IV;
- CSPRNG;
- SHA-256;
- SHA3-256;
- HMAC-SHA256;
- RFC 4231;
- ключи HMAC разных размеров;
- пустой HMAC-ввод;
- incremental HMAC;
- команда `dgst`;
- `--hmac`;
- обязательность `--key`;
- HEX-формат ключа;
- `--output`;
- `--verify`;
- успешная проверка HMAC;
- изменение входного файла;
- неправильный ключ;
- файловые ошибки;
- потоковая обработка;
- совместимость функциональности предыдущих спринтов.

# Структура проекта

```text
CryptoCore/
├── .gitignore
├── README.md
├── pyproject.toml
├── requirements.txt
│
├── docs/
│   ├── nist_final_report.txt
│   └── sprint4_performance.md
│
├── scripts/
│   ├── benchmark_hash.py
│   ├── generate_nist_data.py
│   ├── test_large_hash.py
│   ├── test_large_hmac.py
│   └── test_openssl.ps1
│
├── src/
│   ├── hash/
│   │   ├── __init__.py
│   │   ├── sha256.py
│   │   └── sha3_256.py
│   │
│   ├── mac/
│   │   ├── __init__.py
│   │   └── hmac.py
│   │
│   └── cryptocore/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── csprng.py
│       ├── digest.py
│       ├── file_io.py
│       └── modes/
│           ├── __init__.py
│           ├── common.py
│           ├── ecb.py
│           ├── cbc.py
│           ├── cfb.py
│           ├── ofb.py
│           └── ctr.py
│
└── tests/
    ├── test_cli.py
    ├── test_csprng.py
    ├── test_digest_cli.py
    ├── test_ecb.py
    ├── test_hash_avalanche.py
    ├── test_hmac_cli.py
    ├── test_hmac_vectors.py
    ├── test_modes.py
    ├── test_sha256.py
    └── test_sha3_256.py
```

# Файлы, которые не хранятся в Git

Не добавляются:

```text
.venv/
.idea/
__pycache__/
.pytest_cache/
*.egg-info/

nist_test_data.bin

large_hash_test.bin
large_hmac_test.bin

benchmark_1mb.bin
benchmark_5mb.bin
benchmark_10mb.bin

hash_test.txt
sprint4.txt
sprint4.sha256

sprint5.txt
sprint5.hmac

plaintext.txt
ciphertext.bin
decrypted.txt

cbc.bin
cfb.bin
ofb.bin
ctr.bin

crypto_*.bin
crypto_decrypted_*.txt
cipher_*.bin

openssl_*.bin
openssl_*.txt
result_*.txt
```

Эти файлы являются временными результатами тестов или локальными служебными файлами.

# Версия

Текущая версия:

```text
0.5.0
```

# Финальная проверка

Перед отправкой изменений в GitHub:

```powershell
pytest -q
```

Проверка RFC 4231 вручную:

```powershell
Set-Content -NoNewline -Path sprint5.txt -Value "Hi There"
$key = "0b" * 20
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt
```

Проверка генерации и верификации:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --output sprint5.hmac
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --verify sprint5.hmac
```

Проверка больших файлов:

```powershell
python scripts\test_large_hmac.py --size-mb 16
```

Таким образом, CryptoCore сохраняет функциональность Sprint 1–4 и добавляет поддержку аутентификации и контроля целостности данных через HMAC-SHA256.