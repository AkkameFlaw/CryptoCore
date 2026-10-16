# CryptoCore

**CryptoCore** — учебный консольный проект по реализации и проверке криптографических алгоритмов на Python. Разработка ведётся последовательно: каждый спринт дополняет проект, сохраняя функциональность предыдущих этапов.

**Текущая версия: `0.6.0`** (после обновления версии в `pyproject.toml` и `src/cryptocore/__init__.py`).

## Возможности

| Спринт | Реализовано |
| --- | --- |
| 1 | AES-128 в режиме ECB, PKCS#7, файловый CLI, тесты |
| 2 | Режимы CBC, CFB, OFB и CTR, генерация и обработка IV |
| 3 | CSPRNG на `os.urandom()`, случайные ключи и IV, статистические проверки и NIST STS |
| 4 | Собственные SHA-256 и SHA3-256, `dgst`, потоковое хеширование, эталонные векторы и benchmark |
| 5 | Собственный HMAC-SHA256, `--hmac`, `--key`, `--verify`, RFC 4231 |
| 6 | AES-GCM, Encrypt-then-MAC (AES-CTR + HMAC-SHA256), AAD, проверка аутентификации до расшифрования |

## Установка

Нужен Python 3.10 или новее. Примеры команд приведены для PowerShell в Windows.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Проверка CLI:

```powershell
cryptocore --help
cryptocore dgst --help
```

Проект использует **PyCryptodome** в качестве AES-примитива. Собственные реализации SHA-256, SHA3-256, HMAC, GHASH/GCM и схемы Encrypt-then-MAC расположены в отдельных исходных модулях.

## Sprint 1–2. AES-128 и режимы работы

Поддерживаемые режимы:

- `ecb` — ECB с PKCS#7;
- `cbc` — CBC с PKCS#7;
- `cfb` — CFB без padding;
- `ofb` — OFB без padding;
- `ctr` — CTR без padding.

Формат команды:

```text
cryptocore --algorithm aes --mode MODE --encrypt|--decrypt [--key KEY] --input INPUT [--output OUTPUT] [--iv IV]
```

Для AES-128 вручную заданный ключ содержит **16 байт**, то есть **32 шестнадцатеричных символа**.

Пример ECB:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Пример CBC:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cbc.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

Для CBC, CFB, OFB и CTR при обычном шифровании генерируется случайный IV длиной 16 байт. Формат файла предыдущих режимов:

```text
IV (16 байт) || ciphertext
```

При расшифровании IV обычно считывается из начала файла. Возможность передачи `--iv` сохранена для обратной совместимости.

**Ограничение безопасности:** ECB, CBC, CFB, OFB и CTR в данном CLI сами по себе не обеспечивают проверку подлинности. Для защиты от незаметной подмены рекомендуется выбирать `gcm` или `etm`.

## Sprint 3. CSPRNG

Модуль: `src/cryptocore/csprng.py`.

Функция `generate_random_bytes(num_bytes)` получает случайные данные через `os.urandom()`. Обычный модуль `random` не применяется для криптографических ключей и IV.

При AES-шифровании параметр `--key` можно не передавать: программа создаст случайный ключ AES-128 и выведет его в консоль. При расшифровании ключ обязателен. Сгенерированный ключ следует хранить отдельно от шифртекста и не публиковать.

Для проверки CSPRNG выполнялись генерация 1000 ключей, оценка распределения битов и испытания в NIST Statistical Test Suite. Файлы сборки NIST STS, большие бинарные последовательности и локальные рабочие материалы не относятся к исходному коду проекта и не должны загружаться в репозиторий.

## Sprint 4. SHA-256 и SHA3-256

Собственные реализации:

```text
src/hash/sha256.py
src/hash/sha3_256.py
```

Обе хеш-функции реализованы без вызова `hashlib` для вычисления самих хешей. `hashlib` используется в тестах как независимый эталон.

SHA-256 реализует обработку 512-битных блоков и 64 раунда с правилами FIPS 180-4. SHA3-256 использует губчатую конструкцию Keccak-f[1600] с 24 раундами и rate 136 байт. Обе функции формируют 256-битный результат (64 символа HEX).

Команда вычисления хеша:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
cryptocore dgst --algorithm sha3-256 --input document.pdf
cryptocore dgst --algorithm sha256 --input document.pdf --output document.sha256
```

Результат оформляется как:

```text
HASH_VALUE  INPUT_FILE_PATH
```

Для больших файлов `src/cryptocore/digest.py` читает данные блоками по 8192 байт; целиком в память файл не загружается. Проверяются известные векторы, пустой ввод, многочастное обновление состояния, лавинный эффект и совпадение с системными утилитами.

Эталонные хеши пустой строки:

```text
SHA-256:  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA3-256: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
```

Для отдельной длительной проверки больших файлов предусмотрен `scripts/test_large_hash.py`. Наличие скрипта не означает, что все конфигурации больших файлов уже были фактически протестированы.

### Измерение производительности Sprint 4

Сценарий: `scripts/benchmark_hash.py`. Измерения выполнены на Python 3.14.0, Windows 10.

| Размер | Алгоритм | CryptoCore, с | Эталон | Эталон, с | Замедление | Совпадение |
| ---: | --- | ---: | --- | ---: | ---: | --- |
| 1 МБ | SHA-256 | 6.082333 | sha256sum | 0.342494 | 17.76x | True |
| 1 МБ | SHA3-256 | 7.778663 | OpenSSL | 0.517732 | 15.02x | True |
| 5 МБ | SHA-256 | 33.321969 | sha256sum | 0.171867 | 193.88x | True |
| 5 МБ | SHA3-256 | 40.372300 | OpenSSL | 0.039735 | 1016.05x | True |
| 10 МБ | SHA-256 | 62.086354 | sha256sum | 0.227347 | 273.09x | True |
| 10 МБ | SHA3-256 | 79.184037 | OpenSSL | 0.057318 | 1381.48x | True |

Собственные реализации медленнее низкоуровневых системных версий, что ожидаемо для учебного чистого Python. Во всех указанных измерениях результаты совпали. Автоматически созданный отчёт — `docs/sprint4_performance.md`.

## Sprint 5. HMAC-SHA256

Реализация: `src/mac/hmac.py`. Алгоритм соответствует конструкции RFC 2104 и использует **собственную** SHA-256 из Sprint 4.

```text
HMAC(K, m) = SHA256((K' XOR opad) || SHA256((K' XOR ipad) || m))
```

Здесь `ipad = 0x36`, `opad = 0x5c`, а `K'` — ключ после обработки: ключи длиннее блока SHA-256 (64 байта) сначала хешируются, короткие дополняются нулями. HMAC поддерживает ключи произвольной длины.

HMAC позволяет проверять целостность и подлинность сообщения при наличии общего секретного ключа, но **не шифрует** содержимое.

Для `dgst --hmac` ключ передаётся в HEX, при этом ограничение AES-ключа в 16 байт на HMAC не распространяется.

```powershell
Set-Content -NoNewline -Path sprint5.txt -Value "Hi There"
$key = "0b" * 20
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt
```

Ожидаемый HMAC из RFC 4231:

```text
b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
```

Сохранение и проверка:

```powershell
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --output sprint5.hmac
cryptocore dgst --algorithm sha256 --hmac --key $key --input sprint5.txt --verify sprint5.hmac
```

При совпадении программа выводит `[OK] HMAC verification successful` и возвращает код `0`; при несовпадении сообщает `[ERROR] HMAC verification failed` и возвращает `1`. Сравнение производится через `secrets.compare_digest()`.

В тестах проверяются RFC 4231 (случаи 1–4), пустое сообщение, длины ключа 16/64/100 байт, подмена сообщения, неправильный ключ, `--output`, `--verify` и потоковая обработка. Для отдельного запуска с крупным файлом есть `scripts/test_large_hmac.py`.

## Sprint 6. Аутентифицированное шифрование (AEAD)

В шестом спринте реализованы два механизма, объединяющие конфиденциальность и аутентификацию:

- **AES-GCM** — аутентифицированное шифрование на основе AES-CTR и GHASH.
- **Encrypt-then-MAC (`etm`)** — AES-CTR с отдельным HMAC-SHA256 для проверки подлинности.

**AEAD** позволяет связать шифртекст с дополнительными данными **AAD** (*Additional Authenticated Data*). AAD не шифруются, но включаются в аутентификацию: изменить их без обнаружения нельзя при сохранении защищённого ключа.

### AES-GCM

Реализация: `src/modes/gcm.py`.

Реализованы счётчик CTR, `inc32`, GHASH, умножение в `GF(2^128)` по многочлену `x^128 + x^7 + x^2 + x + 1`, формирование и проверка 128-битного тега. Для базового блочного преобразования используется AES из PyCryptodome, а логика GCM написана в проекте самостоятельно. Реализация сверялась с тестовыми векторами NIST и PyCryptodome.

Стандартный формат выходного файла CLI:

```text
Nonce (12 байт) || Ciphertext || Tag (16 байт)
```

При каждом обычном вызове шифрования создаётся случайный nonce длиной 12 байт. При расшифровании nonce извлекается из начала файла. На уровне класса `GCM` также проверяются nonce иной длины; CLI использует 12-байтный формат.

**Нельзя повторно использовать один и тот же GCM nonce с одним ключом.** Это может нарушить конфиденциальность и защиту от подделки. Случайная генерация снижает вероятность повторения, но не является глобальной гарантией уникальности между независимыми запусками программы.

Шифрование с AAD:

```powershell
Set-Content -NoNewline -Path sprint6.txt -Value "Hello authenticated encryption"
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input sprint6.txt --output sprint6_gcm.bin --aad aabbccddeeff
```

Расшифрование с тем же AAD:

```powershell
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input sprint6_gcm.bin --output sprint6_decrypted.txt --aad aabbccddeeff
```

Ожидаемое сообщение:

```text
[SUCCESS] Decryption completed successfully
```

При неправильном AAD:

```powershell
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input sprint6_gcm.bin --output sprint6_failed.txt --aad 112233445566
```

Ошибка:

```text
[ERROR] Authentication failed: AAD mismatch or ciphertext tampered
```

Код завершения — `1`. Проверка отсутствия выходного файла:

```powershell
Test-Path sprint6_failed.txt
```

Ожидаемое значение — `False` (если файла не было до команды). Если выходной файл уже существовал, при ошибке аутентификации его содержимое остаётся нетронутым.

Параметр `--aad` принимает HEX-строку; если он опущен, AAD пустой. Неверные HEX-символы или нечётная длина отклоняются.

При отдельной передаче `--nonce` (либо совместимого `--iv`) расшифрование GCM принимает **отделённый payload**, содержащий только `ciphertext || tag`, без начального nonce. Для обычного файла `nonce || ciphertext || tag` передавать `--nonce` не нужно.

### Encrypt-then-MAC (EtM)

Реализация: `src/aead/encrypt_then_mac.py`.

EtM шифрует через AES-CTR, после чего вычисляет HMAC-SHA256 для nonce, шифртекста и AAD. Для шифрования и аутентификации используются **разные ключи**, получаемые из 16-байтного master key посредством HMAC-SHA256 с различными контекстными метками (`encryption` и `authentication`).

Формат файла:

```text
Nonce (16 байт) || Ciphertext || HMAC (32 байта)
```

HMAC включает контекст протокола, длины полей, nonce, шифртекст и AAD. При расшифровании **сначала проверяется HMAC**, и только после этого вызывается AES-CTR.

Шифрование:

```powershell
cryptocore --algorithm aes --mode etm --encrypt --key 00112233445566778899aabbccddeeff --input sprint6.txt --output sprint6_etm.bin --aad aabbccddeeff
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode etm --decrypt --key 00112233445566778899aabbccddeeff --input sprint6_etm.bin --output sprint6_etm_decrypted.txt --aad aabbccddeeff
```

Неправильный AAD, ключ либо изменённый nonce, шифртекст или MAC приводят к отказу до расшифрования. Схема EtM здесь является внутренним форматом CryptoCore; её не следует считать совместимой с произвольной сторонней реализацией Encrypt-then-MAC без согласования формата и разделения ключей.

### AAD из файла: `--aad-file`

Для больших AAD в режиме **GCM** поддерживается параметр `--aad-file PATH`. Это расширение не заменяет `--aad`, а позволяет читать бинарные AAD блоками. Одновременно использовать `--aad` и `--aad-file` нельзя. Для режима `etm` доступна передача AAD через HEX-аргумент `--aad`.

```powershell
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input sprint6.txt --output sprint6_gcm.bin --aad-file metadata.bin
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input sprint6_gcm.bin --output sprint6_decrypted.txt --aad-file metadata.bin
```

При изменении `metadata.bin` проверка тега не проходит. Результат расшифрования не записывается в выходной файл.

В `src/modes/gcm.py` чтение потока AAD выполняется кусками до 8192 байт. Добавлены тесты потокового AAD, сравнение с PyCryptodome и сценарий `scripts/test_large_aad.py`.

Проверенный запуск:

```powershell
python scripts\test_large_aad.py --size-mb 16
```

Он создаёт временный AAD-файл, вычисляет AES-GCM, сравнивает результат с PyCryptodome и удаляет тестовые данные. **Проверка на объёме AAD больше фактически доступной оперативной памяти отдельно не проводилась**; для неё скрипт позволяет задать больший размер, однако продолжительность такого теста на чистом Python может быть значительной.

**Ограничение:** текущий CLI для шифруемого файла по-прежнему использует `read_binary()`, то есть загружает сам plaintext/ciphertext в оперативную память. Потоковый режим Sprint 6 относится к AAD; он не означает полностью потокового шифрования произвольно больших файлов.

### Безопасность и поведение при сбое аутентификации

- При несовпадении тега, неверном AAD или подмене защищённых данных расшифрование заканчивается ошибкой.
- Открытый текст не передаётся в `write_binary()` до успешной аутентификации.
- При ошибке проверки отсутствующий выходной файл не создаётся; существующий выходной файл не перезаписывается.
- GCM и EtM не совместимы по формату файлов и не могут использоваться взаимозаменяемо.
- AAD должен совпадать побайтно при шифровании и расшифровании.
- Безопасность зависит от секретности ключа и корректной генерации уникальных nonce.

Эта программа предназначена для учебного изучения криптографических алгоритмов, а не как прошедшая независимый аудит библиотека для защиты реальных секретов.

## Тестирование

Основной запуск:

```powershell
pytest -q
```

Тесты GCM и Encrypt-then-MAC:

```powershell
pytest tests/test_gcm.py tests/test_encrypt_then_mac.py tests/test_aead_cli.py -q
```

Дополнительные тесты nonce и потокового AAD:

```powershell
pytest tests/test_gcm_final.py tests/test_gcm_aad_file.py -v
```

Отдельные долгие сценарии:

```powershell
python scripts\test_large_hmac.py --size-mb 16
python scripts\test_large_aad.py --size-mb 16
python scripts\benchmark_hash.py
```

В Sprint 6 проверены известные ответы NIST для GCM, совместимость с PyCryptodome, полный цикл шифрования, неправильный AAD, подмена шифртекста/тега/nonce, отсутствие выхода при ошибке, сохранение существующего файла, уникальность 1000 nonce, пустой AAD и потоковая обработка AAD разных размеров. Для EtM проверяются те же принципы аутентификации и разделение ключей.

Полный набор тестов предыдущих спринтов сохраняется и запускается через `pytest -q`. Время выполнения может составлять несколько минут из-за SHA-256, SHA3-256 и HMAC, реализованных на чистом Python.

## Структура проекта

```text
CryptoCore/
├── README.md
├── pyproject.toml
├── requirements.txt
├── .gitignore
├── docs/
│   └── sprint4_performance.md
├── scripts/
│   ├── benchmark_hash.py
│   ├── generate_nist_data.py
│   ├── test_large_hash.py
│   ├── test_large_hmac.py
│   ├── test_large_aad.py
│   └── test_openssl.ps1
├── src/
│   ├── aead/
│   │   ├── __init__.py
│   │   └── encrypt_then_mac.py
│   ├── modes/
│   │   ├── __init__.py
│   │   └── gcm.py
│   ├── hash/
│   │   ├── __init__.py
│   │   ├── sha256.py
│   │   └── sha3_256.py
│   ├── mac/
│   │   ├── __init__.py
│   │   └── hmac.py
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
    ├── test_sha3_256.py
    ├── test_gcm.py
    ├── test_encrypt_then_mac.py
    ├── test_aead_cli.py
    ├── test_gcm_final.py
    └── test_gcm_aad_file.py
```

Локальные отчёты NIST STS могут храниться отдельно от репозитория. В структуре показаны исходные файлы и тесты, необходимые для сборки и проверки версии 0.6.0.

## Что не добавляется в Git

В репозитории не должны появляться виртуальное окружение, кэш Python, служебные каталоги IDE, бинарные тестовые файлы, созданные ciphertext/plaintext, временные большие AAD-файлы и секретные ключи:

```gitignore
.venv/
.idea/
__pycache__/
.pytest_cache/
*.egg-info/
benchmark_*mb.bin
large_hash_test.bin
large_hmac_test.bin
large_aad.bin
sprint4.txt
sprint4.sha256
sprint5.txt
sprint5.hmac
sprint6.txt
sprint6_*.bin
sprint6_*.txt
nist_test_data.bin
```

## Версия

**CryptoCore 0.6.0** — SHA-256, SHA3-256, HMAC-SHA256, AES-128 (ECB/CBC/CFB/OFB/CTR), AES-GCM и Encrypt-then-MAC с аутентификацией AAD.