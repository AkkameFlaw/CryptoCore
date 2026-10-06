# CryptoCore

CryptoCore — консольный инструмент для работы с криптографическими алгоритмами.

Проект развивается по спринтам. Каждый следующий спринт расширяет существующую реализацию и сохраняет функциональность предыдущих этапов.

Текущая версия проекта:

```text
0.4.0
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
- тесты новых режимов;
- проверку совместимости с внешними реализациями.

## Sprint 3

В третьем спринте мы добавили:

- отдельный модуль CSPRNG;
- функцию `generate_random_bytes(num_bytes)`;
- использование `os.urandom()`;
- автоматическую генерацию AES-128 ключа;
- вывод сгенерированного ключа в терминал;
- обязательный ключ при расшифровании;
- генерацию IV через общий CSPRNG;
- предупреждение о потенциально слабых ключах;
- тест генерации 1000 уникальных ключей;
- базовую статистическую проверку распределения битов;
- генерацию данных для NIST STS;
- проверку CSPRNG через NIST Statistical Test Suite.

## Sprint 4

В четвёртом спринте мы добавили:

- отдельную команду `dgst`;
- SHA-256, реализованный с нуля;
- SHA3-256, реализованный с нуля;
- отдельный каталог `src/hash/`;
- потоковое хеширование файлов;
- обработку пустых файлов;
- поддержку файлов произвольной длины;
- запись результата в stdout;
- запись результата в файл через `--output`;
- известные тестовые векторы;
- проверку совместимости с системными реализациями;
- тест лавинного эффекта;
- отдельный сценарий проверки файла размером более 1 ГБ;
- измерение производительности SHA-256 и SHA3-256 на файлах нескольких размеров.

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

Установим проект:

```powershell
pip install -e ".[dev]"
```

# Проверка установки

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

# Sprint 1

## ECB

Шифрование:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

ECB использует PKCS#7 padding.

# Sprint 2

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

При расшифровании CryptoCore автоматически считывает первые 16 байт как IV.

Также IV можно передать вручную:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input ciphertext.bin --output decrypted.txt
```

# Sprint 3

## CSPRNG

Реализация находится в:

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

`os.urandom()` получает случайные данные из криптографически стойкого источника операционной системы и предназначен для генерации криптографического материала.

Модуль `random` для генерации ключей и IV не используется.

# Автоматическая генерация ключа

При шифровании параметр `--key` необязателен:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

CryptoCore создаёт случайный AES-128 ключ:

```text
[INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```

Сгенерированный ключ не записывается в зашифрованный файл.

При расшифровании ключ обязателен.

# NIST Statistical Test Suite

CSPRNG был дополнительно проверен с использованием NIST Statistical Test Suite.

Использовались:

```text
100 последовательностей
1 000 000 бит в каждой последовательности
Binary input
Все 15 тестов NIST STS
```

Полный отчёт сохранён:

```text
docs/nist_final_report.txt
```

# Sprint 4

# Структура хеш-функций

Реализации хеш-функций находятся в отдельном каталоге:

```text
src/hash/
├── __init__.py
├── sha256.py
└── sha3_256.py
```

Это отделяет реализации хеш-функций от основной логики CryptoCore.

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

Пример:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
```

Формат результата:

```text
HASH_VALUE  INPUT_FILE_PATH
```

# SHA-256

Реализация находится:

```text
src/hash/sha256.py
```

SHA-256 реализован без использования `hashlib`.

Реализация включает:

- обработку сообщения блоками по 512 бит;
- восемь 32-битных слов состояния;
- 64 раунда;
- раундовые константы;
- message schedule;
- операции Choice и Majority;
- циклические сдвиги;
- SHA-256 padding;
- добавление 64-битной длины сообщения;
- `update()`;
- `digest()`;
- `hexdigest()`.

Результат имеет размер 256 бит и представляется 64 шестнадцатеричными символами в нижнем регистре.

# SHA3-256

Реализация находится:

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
- SHA-3 padding;
- `update()`;
- `digest()`;
- `hexdigest()`.

Для SHA3-256 используется rate:

```text
1088 бит
136 байт
```

# Свойства безопасности

SHA-256 и SHA3-256 формируют хеш длиной 256 бит.

Для идеальной криптографической хеш-функции с выходом 256 бит сложность поиска прообраза составляет порядка:

```text
2^256
```

а сложность поиска коллизии вследствие парадокса дней рождения — порядка:

```text
2^128
```

SHA-256 использует конструкцию Merkle-Damgard.

SHA3-256 основан на Keccak и использует губчатую конструкцию.

Даже небольшое изменение исходных данных приводит к существенному изменению итогового хеша, что проверяется отдельным тестом лавинного эффекта.

SHA-256 и SHA3-256 являются быстрыми криптографическими хеш-функциями и не предназначены для непосредственного хранения пользовательских паролей без специализированного password hashing.

# Запись результата в файл

```powershell
cryptocore dgst --algorithm sha256 --input sprint4.txt --output sprint4.sha256
```

При использовании `--output` результат записывается в файл в формате:

```text
HASH_VALUE  INPUT_FILE_PATH
```

# Разделение CLI

Команда `dgst` не принимает параметры AES:

```text
--key
--mode
--encrypt
--decrypt
--iv
```

Например, команда:

```text
cryptocore dgst --algorithm sha256 --input file.bin --key ...
```

завершается ошибкой аргументов.

# Потоковая обработка файлов

Для хеширования файл не загружается полностью в оперативную память.

Файл читается частями размером:

```text
8192 байт
```

Каждый блок передаётся в:

```python
update()
```

Файловая логика реализована в:

```text
src/cryptocore/digest.py
```

Такой подход позволяет работать с файлами, размер которых превышает доступную оперативную память.

# Пустой ввод

SHA-256 пустого сообщения:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

SHA3-256 пустого сообщения:

```text
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
```

Оба результата проверяются автоматическими тестами.

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

`hashlib` используется только в тестах как независимая эталонная реализация.

# Проверка совместимости

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

# Лавинный эффект

Тест находится:

```text
tests/test_hash_avalanche.py
```

Для проверки используются:

```text
Hello, world!
Hello, world?
```

После изменения небольшой части исходного сообщения сравнивается количество изменившихся битов двух 256-битных хешей.

# Большие файлы

Для отдельной проверки обработки файла размером более 1 ГБ подготовлен:

```text
scripts/test_large_hash.py
```

Запуск:

```powershell
python scripts\test_large_hash.py --size-gb 1
```

Тест вынесен из стандартного `pytest`, поскольку учебная реализация SHA-256 написана на чистом Python и обработка файла такого размера занимает значительное время.

# Производительность хеш-функций

Для Sprint 4 выполнено измерение производительности собственных реализаций SHA-256 и SHA3-256.

Сценарий находится:

```text
scripts/benchmark_hash.py
```

Измерения выполнялись на:

```text
Python 3.14.0
Windows 10
```

Использовались файлы размером:

```text
1 МБ
5 МБ
10 МБ
```

Полученные результаты:

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

Это подтверждает, что собственные реализации CryptoCore вычисляют те же значения хешей, что и системные реализации.

CryptoCore работает медленнее, поскольку SHA-256 и SHA3-256 реализованы в учебных целях на чистом Python, тогда как `sha256sum` и OpenSSL используют оптимизированные низкоуровневые реализации.

Рост времени CryptoCore приблизительно соответствует увеличению объёма обрабатываемых данных.

Полный автоматически сформированный отчёт находится:

```text
docs/sprint4_performance.md
```

# Автоматические тесты

Для запуска:

```powershell
pytest -q
```

На текущем этапе проекта результат:

```text
96 passed
```

Тестируются:

- AES-128;
- ECB;
- CBC;
- CFB;
- OFB;
- CTR;
- PKCS#7;
- ключи и IV;
- CSPRNG;
- CLI;
- SHA-256;
- SHA3-256;
- известные тестовые векторы;
- пустой ввод;
- обработка границ блоков;
- последовательные вызовы `update()`;
- lowercase HEX;
- `dgst`;
- `--output`;
- файловые ошибки;
- запрет AES-параметров для `dgst`;
- потоковая файловая обработка;
- лавинный эффект;
- совместимость предыдущих спринтов.

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
│   └── test_openssl.ps1
│
├── src/
│   ├── hash/
│   │   ├── __init__.py
│   │   ├── sha256.py
│   │   └── sha3_256.py
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

benchmark_1mb.bin
benchmark_5mb.bin
benchmark_10mb.bin

hash_test.txt
sprint4.txt
sprint4.sha256

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

Эти файлы являются временными результатами тестирования или локальными служебными файлами.

# Версия

```text
0.4.0
```

# Финальная проверка

```powershell
pytest -q
```

Текущий результат:

```text
96 passed
```

Измерение производительности:

```powershell
python scripts\benchmark_hash.py
```

Результаты:

```text
docs/sprint4_performance.md
```

Таким образом, CryptoCore сохраняет функциональность предыдущих спринтов и реализует хеширование SHA-256 и SHA3-256, потоковую обработку файлов, внешнюю проверку корректности и измерение производительности.