# CryptoCore

**CryptoCore** — учебный проект по реализации и тестированию криптографических алгоритмов на Python с интерфейсом командной строки (CLI).

Проект разрабатывается поэтапно. Каждый следующий спринт расширяет функциональность предыдущих, сохраняя совместимость существующих команд.

**Текущая версия: 0.7.0**

## 1. Реализованная функциональность

| Спринт | Функциональность |
|---|---|
| Sprint 1 | AES-128, ECB, PKCS#7, CLI, обработка файлов |
| Sprint 2 | Режимы CBC, CFB, OFB и CTR, генерация IV |
| Sprint 3 | CSPRNG через `os.urandom()`, генерация ключей, NIST STS |
| Sprint 4 | Собственные SHA-256 и SHA3-256, потоковое хеширование, измерение производительности |
| Sprint 5 | Собственный HMAC-SHA256, RFC 2104, проверка целостности |
| Sprint 6 | AES-GCM, GHASH, Encrypt-then-MAC, AAD, аутентифицированное шифрование |
| Sprint 7 | PBKDF2-HMAC-SHA256, иерархия ключей, команда `derive`, соль и итерации |

## 2. Требования и установка

Для работы необходим Python 3.10 или новее.

Используемые зависимости:

- PyCryptodome — блочный примитив AES;
- pytest — автоматизированное тестирование;
- стандартная библиотека Python.

Для дополнительных проверок использовались OpenSSL, `sha256sum` и NIST Statistical Test Suite.

### Установка на Windows

Создадим виртуальное окружение:

```powershell
python -m venv .venv
```

Активируем:

```powershell
.\.venv\Scripts\Activate.ps1
```

Установим зависимости:

```powershell
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Проверим команды:

```powershell
cryptocore --help
cryptocore dgst --help
cryptocore derive --help
```

## 3. Sprint 1 — AES-128 в режиме ECB

В первом спринте реализована работа с AES-128 в режиме ECB.

Для ключа AES-128 требуется 16 байт, передаваемых в CLI как 32 шестнадцатеричных символа.

Шифрование:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Для ECB используется PKCS#7 padding.

Реализованы проверки корректности ключа, обработки файлов, дополнения данных, ошибок ввода и полного цикла шифрования и расшифрования.

ECB сохраняет структуру повторяющихся блоков и не рекомендуется для защиты реальных конфиденциальных данных.

## 4. Sprint 2 — дополнительные режимы AES

Реализованы CBC, CFB, OFB и CTR.

| Режим | Padding | IV |
|---|---|---|
| ECB | PKCS#7 | Не применяется |
| CBC | PKCS#7 | 16 байт |
| CFB | Не применяется | 16 байт |
| OFB | Не применяется | 16 байт |
| CTR | Не применяется | 16 байт |

Пример CBC:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cbc.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

Для режимов CBC, CFB, OFB и CTR стандартный формат выходного файла:

```text
IV (16 байт) || Ciphertext
```

IV автоматически генерируется при шифровании и извлекается из файла при расшифровании.

Режимы CBC, CFB, OFB и CTR сами по себе не гарантируют подлинность данных. Для получения аутентифицированного шифрования в Sprint 6 добавлены GCM и Encrypt-then-MAC.

## 5. Sprint 3 — криптографически стойкий генератор случайных данных

Реализация находится в `src/cryptocore/csprng.py`.

Основная функция:

```python
generate_random_bytes(num_bytes)
```

Источником случайных данных служит `os.urandom()`.

Для криптографических ключей и IV обычный генератор `random` не используется.

При AES-шифровании ключ можно не указывать. В этом случае CryptoCore автоматически генерирует случайный ключ AES-128 и выводит его HEX-представление в терминал.

Пример:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

Сгенерированный ключ необходимо сохранить отдельно, поскольку при расшифровании он обязателен.

Для проверки генератора выполнялись тесты уникальности ключей, статистические проверки битового распределения и испытания через NIST Statistical Test Suite.

## 6. Sprint 4 — SHA-256 и SHA3-256

Реализации:

```text
src/hash/sha256.py
src/hash/sha3_256.py
```

SHA-256 и SHA3-256 реализованы самостоятельно, без использования `hashlib` непосредственно в алгоритмах.

SHA-256 использует обработку 512-битных блоков и 64 раунда. SHA3-256 использует губчатую конструкцию Keccak-f[1600].

Обе функции возвращают результат длиной 256 бит.

### Вычисление хеша

SHA-256:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
```

SHA3-256:

```powershell
cryptocore dgst --algorithm sha3-256 --input document.pdf
```

Запись результата:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf --output document.sha256
```

Формат:

```text
HASH_VALUE  INPUT_FILE_PATH
```

Для хеширования файлов используется потоковое чтение блоками по 8192 байт.

Проверены известные тестовые векторы, обработка пустого ввода, многократное обновление состояния, лавинный эффект и совместимость с системными утилитами.

### Измерение производительности

Сценарий:

```text
scripts/benchmark_hash.py
```

Результаты измерений на Python 3.14.0, Windows 10:

| Размер | Алгоритм | CryptoCore, с | Системная утилита | Система, с | Замедление | Совпадение |
|---:|---|---:|---|---:|---:|---|
| 1 МБ | SHA-256 | 6.082333 | sha256sum | 0.342494 | 17.76× | True |
| 1 МБ | SHA3-256 | 7.778663 | OpenSSL | 0.517732 | 15.02× | True |
| 5 МБ | SHA-256 | 33.321969 | sha256sum | 0.171867 | 193.88× | True |
| 5 МБ | SHA3-256 | 40.372300 | OpenSSL | 0.039735 | 1016.05× | True |
| 10 МБ | SHA-256 | 62.086354 | sha256sum | 0.227347 | 273.09× | True |
| 10 МБ | SHA3-256 | 79.184037 | OpenSSL | 0.057318 | 1381.48× | True |

Во всех измерениях результаты CryptoCore совпали с эталонными.

Подробный отчёт:

```text
docs/sprint4_performance.md
```

## 7. Sprint 5 — HMAC-SHA256

Реализация:

```text
src/mac/hmac.py
```

HMAC-SHA256 реализован по RFC 2104 с использованием собственной SHA-256 из Sprint 4.

Формула:

```text
HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
```

HMAC использует секретный ключ для контроля целостности и подлинности сообщения.

Ключи длиной более 64 байт предварительно хешируются. Короткие ключи дополняются нулями.

### Генерация HMAC

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
```

Ключ для HMAC может иметь переменную длину.

### Сохранение HMAC

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac
```

### Проверка HMAC

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify message.hmac
```

При успешной проверке:

```text
[OK] HMAC verification successful
```

При несовпадении:

```text
[ERROR] HMAC verification failed
```

Для сравнения используется `secrets.compare_digest()`.

Автоматические тесты проверяют RFC 4231, ключи разных размеров, пустой файл, изменение сообщения, неправильный ключ и обработку файлов по частям.

Для самостоятельной проверки большого файла предусмотрен `scripts/test_large_hmac.py`.

## 8. Sprint 6 — аутентифицированное шифрование

В шестом спринте добавлены два механизма:

- AES-GCM;
- Encrypt-then-MAC (AES-CTR + HMAC-SHA256).

Эти механизмы обеспечивают конфиденциальность и проверку подлинности данных.

### 8.1. AES-GCM

Реализация:

```text
src/modes/gcm.py
```

GCM включает AES-CTR, GHASH и операции умножения в конечном поле GF(2^128).

Логика GCM реализована самостоятельно, при этом в качестве блочного примитива AES используется PyCryptodome.

Стандартный формат файла:

```text
Nonce (12 байт) || Ciphertext || Tag (16 байт)
```

Nonce создаётся автоматически при шифровании.

### 8.2. Associated Authenticated Data (AAD)

AAD — дополнительные данные, которые не шифруются, но участвуют в аутентификации.

Например, AAD могут содержать сведения о версии формата или идентификатор сообщения.

Шифрование с AAD:

```powershell
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin --aad aabbccddeeff
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt --aad aabbccddeeff
```

При правильном ключе, AAD и теге выводится:

```text
[SUCCESS] Decryption completed successfully
```

Если AAD изменён или данные повреждены, происходит отказ:

```text
[ERROR] Authentication failed: AAD mismatch or ciphertext tampered
```

При провале аутентификации расшифрованные данные не записываются.

### 8.3. AAD из файла

Для GCM реализован дополнительный параметр `--aad-file`.

```powershell
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin --aad-file metadata.bin
```

```powershell
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt --aad-file metadata.bin
```

AAD считываются по частям, без полной загрузки AAD-файла в память.

Одновременно указывать `--aad` и `--aad-file` нельзя.

Для проверки больших AAD создан:

```text
scripts/test_large_aad.py
```

Успешно проверен сценарий с AAD размером 16 МиБ. Фактический тест с AAD больше доступной оперативной памяти отдельно не проводился.

### 8.4. Encrypt-then-MAC

Реализация:

```text
src/aead/encrypt_then_mac.py
```

Схема объединяет AES-CTR и собственный HMAC-SHA256.

Из master key через HMAC с отдельными контекстами получаются два разных ключа:

- ключ шифрования;
- ключ аутентификации.

Формат файла:

```text
Nonce (16 байт) || Ciphertext || HMAC (32 байта)
```

Шифрование:

```powershell
cryptocore --algorithm aes --mode etm --encrypt --key 00112233445566778899aabbccddeeff --input plaintext.txt --output ciphertext.bin --aad aabbccddeeff
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode etm --decrypt --key 00112233445566778899aabbccddeeff --input ciphertext.bin --output decrypted.txt --aad aabbccddeeff
```

Перед расшифрованием обязательно проверяется HMAC.

### 8.5. Проверки безопасности

Для Sprint 6 выполнены:

- тесты GCM по известным векторам NIST;
- сравнение с PyCryptodome;
- обнаружение изменения AAD;
- обнаружение изменения nonce, шифртекста и тега;
- проверка отсутствия выходного файла после ошибки аутентификации;
- проверка сохранения существующего файла;
- тест 1000 уникальных nonce;
- проверка пустого AAD;
- проверка потокового чтения AAD.

Повторное использование nonce с одним ключом GCM недопустимо.

## 9. Sprint 7 — PBKDF2 и иерархия ключей

Седьмой спринт предназначен для получения ключевого материала из паролей и создания отдельных ключей из master key.

Реализованы:

```text
src/kdf/pbkdf2.py
src/kdf/hkdf.py
```

Обе реализации используют собственный HMAC-SHA256 из Sprint 5.

### 9.1. PBKDF2-HMAC-SHA256

PBKDF2 — функция получения криптографического ключа из пароля с использованием salt и заданного числа итераций.

Реализация соответствует конструкции PBKDF2 по RFC 2898.

Входные параметры:

- пароль;
- salt;
- число итераций;
- требуемая длина результата.

Результат представляет собой бинарный ключ заданной длины.

Алгоритм вычисляет последовательность блоков:

```text
DK = T1 || T2 || ... || Tn
```

Каждый блок строится из результатов HMAC:

```text
Ti = U1 XOR U2 XOR ... XOR Uc
```

где:

```text
U1 = HMAC(P, S || INT_32_BE(i))
Uj = HMAC(P, Uj-1)
```

Чем больше итераций, тем дороже вычисление ключа, в том числе для атакующего, перебирающего пароли.

Однако PBKDF2 не компенсирует использование слабых или предсказуемых паролей.

### 9.2. Команда derive

Добавлена подкоманда:

```text
cryptocore derive
```

Общий формат:

```text
cryptocore derive --algorithm pbkdf2 --password PASSWORD [--salt SALT] [--iterations COUNT] [--length LENGTH] [--output FILE]
```

Поддерживаемые параметры:

| Параметр | Назначение | Значение по умолчанию |
|---|---|---|
| `--algorithm` | Алгоритм получения ключа | `pbkdf2` |
| `--password` | Пароль в текстовом виде | Обязателен один источник пароля |
| `--password-env` | Имя переменной окружения с паролем | Не задан |
| `--password-file` | Файл с паролем | Не задан |
| `--salt` | Salt в HEX | Случайные 16 байт |
| `--iterations` | Число итераций | 100000 |
| `--length` | Длина ключа в байтах | 32 |
| `--output` | Путь сохранения бинарного ключа | Не задан |

Пример получения ключа:

```powershell
cryptocore derive --algorithm pbkdf2 --password "password" --salt 73616c74 --iterations 1 --length 32
```

Результат:

```text
120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b  73616c74
```

Формат вывода:

```text
KEY_HEX  SALT_HEX
```

Это значение соответствует PBKDF2-HMAC-SHA256.

Важно: в RFC 6070 приведены тестовые векторы PBKDF2-HMAC-SHA1. Для проверки реализации с HMAC-SHA256 в CryptoCore используются соответствующие SHA-256-векторы и независимые эталонные вычисления.

### 9.3. Автоматический salt

Если `--salt` не указан, программа генерирует случайный 16-байтный salt через CSPRNG.

Пример:

```powershell
cryptocore derive --password "password" --iterations 100000 --length 32
```

Salt не является секретом, но его необходимо сохранять вместе с информацией, необходимой для воспроизведения ключа.

При получении ключа повторно необходимо использовать точно такие же пароль, salt, количество итераций и длину.

В тестах проверена генерация 1000 salt без дубликатов.

### 9.4. Сохранение ключа

Результат можно сохранить через `--output`:

```powershell
cryptocore derive --password "password" --salt 73616c74 --iterations 2 --length 32 --output sprint7.key
```

В файл записывается именно бинарный ключ, а не строка с HEX-символами.

Для 32-байтного ключа размер файла составит ровно 32 байта.

Salt не добавляется в этот файл автоматически.

Команда при этом по-прежнему выводит ключ и salt в терминал, поэтому результаты необходимо защищать от постороннего доступа.

### 9.5. Пароль из переменной окружения

Для снижения риска попадания пароля в историю команд можно использовать `--password-env`.

Пример PowerShell:

```powershell
$env:CRYPTOCORE_PASSWORD = "TestPassword123!"
cryptocore derive --password-env CRYPTOCORE_PASSWORD --iterations 100000 --length 32
Remove-Item Env:\CRYPTOCORE_PASSWORD
```

Также поддерживается `--password-file` для чтения точных бинарных байтов пароля из файла.

Следует учитывать, что переменные окружения и файлы с паролями тоже требуют защиты. Python не гарантирует немедленного безопасного удаления всех копий пароля из оперативной памяти.

### 9.6. Иерархия ключей

Функция:

```python
derive_key(master_key, context, length)
```

Реализация находится в `src/kdf/hkdf.py`.

Она использует собственный HMAC-SHA256 и строит последовательность блоков:

```text
HMAC(master_key, context || counter)
```

Контекст задаёт назначение производного ключа.

Пример:

```python
from kdf import derive_key

master_key = b"0" * 32

encryption_key = derive_key(
    master_key,
    "encryption",
    16,
)

authentication_key = derive_key(
    master_key,
    "authentication",
    32,
)

print("Encryption:", encryption_key.hex())
print("Authentication:", authentication_key.hex())
print("Different:", encryption_key != authentication_key)
```

При одинаковом master key и контексте результат детерминированный.

Разные контексты позволяют получать разные ключи для разных назначений.

Эта функция является упрощённой HMAC-основой для иерархии ключей по требованиям проекта, а не полной реализацией HKDF-Extract/HKDF-Expand из RFC 5869.

### 9.7. Проверка PBKDF2 через OpenSSL

Корректность собственной реализации подтверждена независимым вычислением через OpenSSL 3.6.4.

Команда:

```powershell
openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:password -kdfopt hexsalt:73616c74 -kdfopt iter:2 -binary -out openssl_pbkdf2.bin PBKDF2
```

Оба ключа совпали:

```text
CryptoCore: ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
OpenSSL:    ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
Match: True
```

Это подтверждает совместимость PBKDF2-HMAC-SHA256 с независимой реализацией OpenSSL.

### 9.8. Производительность PBKDF2

Измерения выполнялись с помощью:

```text
scripts/benchmark_pbkdf2.py
```

Среда:

```text
Python 3.14.0
Windows 10
```

Параметры:

```text
Алгоритм: PBKDF2-HMAC-SHA256
Длина ключа: 32 байта
```

Результаты:

| Итерации | CryptoCore, с | hashlib, с | Замедление | Совпадение |
|---:|---:|---:|---:|---|
| 10 000 | 8.411483 | 0.009488 | 886.58× | True |
| 100 000 | 81.309812 | 0.102087 | 796.48× | True |
| 1 000 000 | 772.445409 | 0.940391 | 821.41× | True |

При всех трёх значениях количества итераций результаты совпали.

Собственная реализация существенно медленнее `hashlib`, поскольку PBKDF2, HMAC-SHA256 и SHA-256 написаны на чистом Python.

Время выполнения увеличивается примерно пропорционально количеству итераций.

Тест с одним миллионом итераций занял 772,445409 секунды, или приблизительно 12 минут 52 секунды.

Это подтверждает корректную обработку миллиона итераций, но также показывает, что реализация предназначена для учебных целей и не оптимизирована для производительного использования.

Отчёт:

```text
docs/sprint7_performance.md
```

Структурированные результаты:

```text
docs/sprint7_performance.json
```

### 9.9. Замечания по безопасности PBKDF2

Для безопасного использования PBKDF2 необходимо:

1. Применять достаточно длинные и непредсказуемые пароли.
2. Генерировать новый случайный salt для каждого независимого получения ключа из пароля.
3. Использовать salt длиной не менее 16 байт.
4. Выбирать количество итераций с учётом требований безопасности и возможностей системы.
5. Сохранять параметры PBKDF2, необходимые для повторного вычисления ключа.
6. Не публиковать полученные ключи и пароли.
7. Не передавать реальные пароли через командную строку, если существует более безопасный способ ввода.

Количество итераций по умолчанию в CryptoCore — 100000 — выбрано по техническому заданию. Его не следует считать универсальной современной рекомендацией для производственных систем.

Для новых систем хранения паролей предпочтительно рассматривать специализированные функции, устойчивые к массовому перебору, например Argon2id.

## 10. Автоматические тесты

Все тесты запускаются командой:

```powershell
pytest -q
```

Зафиксированный результат после Sprint 7:

```text
274 passed in 116.04s
```

Тесты Sprint 7 отдельно:

```powershell
pytest tests/test_pbkdf2_vectors.py tests/test_key_hierarchy.py tests/test_derive_cli.py -q
```

Результат:

```text
53 passed in 3.83s
```

Проверяются алгоритмы предыдущих спринтов, PBKDF2, длины производных ключей, различные пароли и salt, автоматическая генерация salt, бинарный вывод, обработка неверных аргументов, детерминированность и разделение контекстов.

## 11. Структура проекта

```text
CryptoCore/
├── .gitignore
├── README.md
├── pyproject.toml
├── requirements.txt
├── docs/
│   ├── sprint4_performance.md
│   ├── sprint7_performance.md
│   └── sprint7_performance.json
├── scripts/
│   ├── generate_nist_data.py
│   ├── test_openssl.ps1
│   ├── benchmark_hash.py
│   ├── benchmark_pbkdf2.py
│   ├── test_large_hash.py
│   ├── test_large_hmac.py
│   └── test_large_aad.py
├── src/
│   ├── aead/
│   │   ├── __init__.py
│   │   └── encrypt_then_mac.py
│   ├── hash/
│   │   ├── __init__.py
│   │   ├── sha256.py
│   │   └── sha3_256.py
│   ├── kdf/
│   │   ├── __init__.py
│   │   ├── pbkdf2.py
│   │   └── hkdf.py
│   ├── mac/
│   │   ├── __init__.py
│   │   └── hmac.py
│   ├── modes/
│   │   ├── __init__.py
│   │   └── gcm.py
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
    ├── test_gcm_aad_file.py
    ├── test_pbkdf2_vectors.py
    ├── test_key_hierarchy.py
    └── test_derive_cli.py
```

## 12. Файлы, исключаемые из Git

В репозиторий не следует добавлять виртуальное окружение, кэш, временные файлы и реальные криптографические секреты.

Примеры правил `.gitignore`:

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
nist_test_data.bin

sprint4.txt
sprint4.sha256
sprint5.txt
sprint5.hmac
sprint6.txt
sprint6_*.bin
sprint6_*.txt
sprint7.key
openssl_pbkdf2.bin
```

Файлы `docs/sprint4_performance.md`, `docs/sprint7_performance.md` и `docs/sprint7_performance.json` являются отчётными материалами и должны оставаться в репозитории.

## 13. Итоги разработки

По состоянию на Sprint 7 в CryptoCore реализованы симметричное шифрование AES-128, криптографические хеш-функции, HMAC, аутентифицированное шифрование и получение ключевого материала через PBKDF2.

Криптографические функции проверялись тестовыми векторами и сравнением с независимыми реализациями. Для SHA-256, SHA3-256 и PBKDF2 выполнены измерения производительности.

Все 274 автоматических теста проекта завершились успешно.

**Версия проекта: 0.7.0.**

CryptoCore является учебной реализацией криптографических алгоритмов и не должен рассматриваться как прошедшее профессиональный аудит программное средство для защиты реальных секретных данных.