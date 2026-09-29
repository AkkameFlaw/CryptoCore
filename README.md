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
- проверку совместимости ECB с OpenSSL.

## Sprint 2

Во втором спринте мы добавили:

- CBC;
- CFB;
- OFB;
- CTR;
- автоматическую генерацию IV;
- хранение IV в начале зашифрованного файла;
- передачу IV через CLI при расшифровании;
- проверку IV;
- автоматические тесты новых режимов;
- проверку совместимости с PyCryptodome;
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
- потоковое хеширование файлов;
- обработку пустых файлов;
- поддержку файлов произвольной длины;
- запись результата хеширования в stdout;
- запись результата в файл через `--output`;
- известные тестовые векторы;
- проверку результатов через стандартные реализации;
- тест лавинного эффекта;
- отдельный сценарий проверки файла размером более 1 ГБ.

# Требования

Для запуска проекта понадобятся:

- Python 3.10 или новее;
- PyCryptodome;
- pytest.

Для дополнительных внешних проверок использовались:

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

Установим проект вместе с зависимостями:

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

Для шифрования используется AES со 128-битным ключом.

Если ключ задаётся вручную, он передаётся в виде HEX-строки длиной 32 символа:

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

Основной формат:

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

## Проверка полного цикла

Создадим тестовый файл:

```powershell
Set-Content -NoNewline -Path plaintext.txt -Value "CryptoCore Sprint 1 test"
```

Зашифруем:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифруем:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Сравним хэши:

```powershell
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash decrypted.txt).Hash
```

Ожидаемый результат:

```text
True
```

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

```powershell
cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cfb.bin --output decrypted.txt
```

CFB не использует padding.

## OFB

```powershell
cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ofb.bin
```

```powershell
cryptocore --algorithm aes --mode ofb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ofb.bin --output decrypted.txt
```

OFB не использует padding.

## CTR

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ctr.bin
```

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --input ctr.bin --output decrypted.txt
```

CTR не использует padding.

# Работа с IV

Для CBC, CFB, OFB и CTR используется IV длиной 16 байт.

При шифровании IV создаётся автоматически через CSPRNG.

Формат зашифрованного файла:

```text
<16-byte IV><ciphertext>
```

При обычном расшифровании CryptoCore автоматически считывает первые 16 байт файла как IV.

Также IV можно передать вручную:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input ciphertext.bin --output decrypted.txt
```

Если используется `--iv`, входной файл должен содержать непосредственно ciphertext без IV в начале.

# Проверка Sprint 2

Для автоматической проверки совместимости используется:

```text
scripts/test_openssl.ps1
```

Запуск:

```powershell
.\scripts\test_openssl.ps1
```

Проверяется совместимость в направлениях:

```text
CryptoCore -> внешняя реализация
внешняя реализация -> CryptoCore
```

для режимов:

```text
CBC
CFB
OFB
CTR
```

# Sprint 3

## CSPRNG

Для генерации криптографически стойких случайных данных используется модуль:

```text
src/cryptocore/csprng.py
```

Основная функция:

```python
generate_random_bytes(num_bytes)
```

Она использует:

```python
os.urandom()
```

`os.urandom()` получает случайные данные из криптографически стойкого источника операционной системы и предназначен для генерации криптографического материала.

Модуль `random` для ключей и IV не используется.

При ошибке системного источника случайности модуль CSPRNG формирует контролируемую ошибку приложения.

# Автоматическая генерация ключа

При шифровании параметр `--key` необязателен.

Например:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

Если ключ не передан, CryptoCore создаёт случайный ключ AES-128 и выводит его один раз:

```text
[INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```

Сгенерированный ключ не записывается в ciphertext.

Для последующего расшифрования ключ необходимо сохранить отдельно.

# Расшифрование

При расшифровании ключ обязателен:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 1a2b3c4d5e6f7890fedcba9876543210 --input ciphertext.bin --output decrypted.txt
```

Если ключ отсутствует, программа завершится с ошибкой.

# Предупреждение о потенциально слабом ключе

Например:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 00000000000000000000000000000000 --input plaintext.txt --output weak.bin
```

Программа выводит предупреждение:

```text
[WARNING] Provided key appears weak.
```

и продолжает выполнение.

# Тестирование CSPRNG

В автоматических тестах проверяются:

- генерация 1000 ключей длиной 16 байт;
- отсутствие повторений среди этих ключей;
- базовое распределение битов;
- корректная длина результата;
- обработка отрицательного размера;
- обработка неправильного типа;
- обработка ошибки `os.urandom()`.

# NIST Statistical Test Suite

Для дополнительной статистической проверки CSPRNG использовался NIST Statistical Test Suite.

Тестовые данные создавались с помощью:

```python
generate_random_bytes()
```

Для проверки использовались:

```text
100 последовательностей
1 000 000 бит в каждой последовательности
Binary input
Все 15 тестов NIST STS
```

Запуск:

```bash
./assess.exe 1000000
```

Были выполнены:

- Frequency;
- Block Frequency;
- Cumulative Sums;
- Runs;
- Longest Run of Ones;
- Rank;
- Discrete Fourier Transform;
- Non-overlapping Template Matching;
- Overlapping Template Matching;
- Universal Statistical;
- Approximate Entropy;
- Random Excursions;
- Random Excursions Variant;
- Serial;
- Linear Complexity.

Для основных тестов итоговый отчёт указал минимальную допустимую долю прохождения приблизительно:

```text
96/100
```

Для Random Excursions и Random Excursions Variant:

```text
61/65
```

Полученные значения `PROPORTION` соответствовали этим порогам.

Примеры результатов:

```text
Frequency              97/100
BlockFrequency        100/100
Runs                    97/100
LongestRun              99/100
Rank                   100/100
FFT                     99/100
OverlappingTemplate     99/100
Universal               98/100
ApproximateEntropy      99/100
LinearComplexity       100/100
```

В отчёте присутствовали отдельные значения uniformity `P-VALUE` ниже `0.01`:

```text
NonOverlappingTemplate
P-VALUE = 0.003201
PROPORTION = 99/100

Serial
P-VALUE = 0.001112
PROPORTION = 100/100
```

Эти отдельные отклонения не сопровождались массовыми отказами последовательностей.

Полный отчёт сохранён в:

```text
docs/nist_final_report.txt
```

# Sprint 4

## Хеширование

Для вычисления криптографических хешей используется отдельная команда:

```text
cryptocore dgst
```

Поддерживаются алгоритмы:

```text
sha256
sha3-256
```

SHA-256 и SHA3-256 реализованы внутри CryptoCore без использования `hashlib` в самих реализациях алгоритмов.

`hashlib` используется только в тестах как независимая эталонная реализация.

# SHA-256

Реализация находится в:

```text
src/cryptocore/hashes/sha256.py
```

Реализация включает:

- внутреннее состояние из восьми 32-битных слов;
- обработку блоков по 512 бит;
- 64 раунда преобразования;
- раундовые константы SHA-256;
- расширение расписания сообщения;
- padding;
- добавление 64-битной длины исходного сообщения;
- поддержку последовательных вызовов `update()`;
- `digest()`;
- `hexdigest()`.

Результат SHA-256 имеет размер 256 бит и выводится как 64 шестнадцатеричных символа в нижнем регистре.

# SHA3-256

Реализация находится в:

```text
src/cryptocore/hashes/sha3_256.py
```

Реализация включает:

- губчатую конструкцию SHA-3;
- состояние Keccak-f[1600];
- перестановку Keccak;
- 24 раунда;
- операции Theta;
- Rho;
- Pi;
- Chi;
- Iota;
- domain separation для SHA-3;
- padding;
- поддержку последовательных вызовов `update()`;
- `digest()`;
- `hexdigest()`.

Для SHA3-256 используется rate размером 1088 бит, то есть 136 байт.

Результат SHA3-256 имеет размер 256 бит и выводится как 64 шестнадцатеричных символа в нижнем регистре.

# Свойства безопасности хеш-функций

SHA-256 и SHA3-256 формируют хеш длиной 256 бит.

Для идеальной криптографической хеш-функции с выходом 256 бит сложность поиска прообраза составляет порядка `2^256` операций, а сложность поиска коллизии вследствие парадокса дней рождения — порядка `2^128` операций.

SHA-256 использует конструкцию Merkle-Damgard и обрабатывает сообщение блоками по 512 бит.

SHA3-256 основан на алгоритме Keccak и использует губчатую конструкцию с перестановкой Keccak-f[1600].

Оба алгоритма предназначены для вычисления message digest и могут использоваться для контроля целостности данных.

Даже небольшое изменение исходных данных приводит к существенному изменению итогового хеша, что дополнительно проверяется в проекте тестом лавинного эффекта.

SHA-256 и SHA3-256 являются быстрыми криптографическими хеш-функциями. Для непосредственного хранения пользовательских паролей без специализированных алгоритмов password hashing их использовать не следует.

# Команда dgst

Формат:

```text
cryptocore dgst --algorithm ALGORITHM --input INPUT_FILE [--output OUTPUT_FILE]
```

Например:

```powershell
cryptocore dgst --algorithm sha256 --input document.pdf
```

Формат вывода:

```text
HASH_VALUE  INPUT_FILE_PATH
```

Например:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  sprint4.txt
```

SHA3-256:

```powershell
cryptocore dgst --algorithm sha3-256 --input sprint4.txt
```

Пример результата для файла, содержащего `abc`:

```text
3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532  sprint4.txt
```

# Запись хеша в файл

Можно использовать:

```powershell
cryptocore dgst --algorithm sha256 --input sprint4.txt --output sprint4.sha256
```

Результат записывается в том же формате:

```text
HASH_VALUE  INPUT_FILE_PATH
```

При использовании `--output` результат не выводится в stdout.

# Разделение CLI

Команда:

```text
cryptocore dgst
```

не принимает параметры шифрования:

```text
--key
--mode
--encrypt
--decrypt
--iv
```

Операции AES и операции хеширования имеют отдельные интерфейсы.

# Потоковая обработка файлов

Для хеширования файл не загружается полностью в оперативную память.

Файл читается блоками:

```text
8192 байт
```

Каждый блок последовательно передаётся в:

```python
update()
```

Благодаря этому потребление оперативной памяти практически не зависит от размера входного файла.

За файловую обработку хеширования отвечает:

```text
src/cryptocore/digest.py
```

# Пустой ввод

SHA-256 для пустого сообщения:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

SHA3-256 для пустого сообщения:

```text
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
```

Оба случая проверяются автоматическими тестами.

# Известные тестовые векторы

Для SHA-256 проверяются, в частности:

```text
SHA-256("")
SHA-256("abc")
```

а также длинный тестовый вектор:

```text
abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq
```

Для SHA-256 также проверяется сообщение из одного миллиона символов:

```text
a
```

Для SHA3-256 проверяются:

```text
SHA3-256("")
SHA3-256("abc")
SHA3-256("The quick brown fox jumps over the lazy dog")
```

и сообщение из одного миллиона символов `a`.

# Проверка совместимости

Для SHA-256 результат CryptoCore был проверен через:

```bash
sha256sum hash_test.txt
```

и:

```powershell
cryptocore dgst --algorithm sha256 --input hash_test.txt
```

Полученные значения совпали.

Для SHA3-256 результат CryptoCore был проверен через внешнюю реализацию OpenSSL:

```bash
openssl dgst -sha3-256 hash_test.txt
```

и:

```powershell
cryptocore dgst --algorithm sha3-256 --input hash_test.txt
```

Полученные значения совпали.

Дополнительно SHA-256 и SHA3-256 автоматически сравниваются со стандартным модулем Python `hashlib` в тестах.

# Лавинный эффект

В проекте присутствует:

```text
tests/test_hash_avalanche.py
```

Для проверки используются близкие входные сообщения:

```text
Hello, world!
Hello, world?
```

Для каждого алгоритма сравниваются 256 бит двух хешей.

Тест проверяет, что изменение небольшой части исходного сообщения приводит к изменению большого количества битов итогового хеша.

# Большие файлы

Основная реализация хеширования использует потоковое чтение, поэтому не требует загрузки всего файла в память.

Для ручной проверки файла размером более 1 ГБ подготовлен:

```text
scripts/test_large_hash.py
```

Запуск:

```powershell
python scripts\test_large_hash.py --size-gb 1
```

Скрипт:

1. создаёт тестовый файл размером немного больше 1 ГБ;
2. вычисляет эталонный SHA-256 через `hashlib`;
3. вычисляет SHA-256 через CryptoCore;
4. сравнивает результаты.

Ожидаемый итог:

```text
Match:    True
```

Этот тест намеренно не входит в стандартный запуск `pytest`, поскольку SHA-256 реализован на чистом Python в учебных целях и обработка файла такого размера занимает значительно больше времени, чем библиотечная реализация.

Временный файл:

```text
large_hash_test.bin
```

не хранится в Git-репозитории.

# Автоматические тесты

Для запуска всех тестов:

```powershell
pytest -q
```

Тестируются:

- AES-128;
- ECB;
- CBC;
- CFB;
- OFB;
- CTR;
- PKCS#7;
- ключи;
- IV;
- CLI;
- файловые операции;
- CSPRNG;
- генерация ключей;
- SHA-256;
- SHA3-256;
- известные тестовые векторы;
- пустые сообщения;
- поблочное обновление состояния;
- границы блоков;
- вывод в нижнем регистре;
- команда `dgst`;
- `--output`;
- обработка отсутствующих файлов;
- неправильный алгоритм;
- запрет AES-параметров для `dgst`;
- лавинный эффект;
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
│   └── nist_final_report.txt
│
├── scripts/
│   ├── generate_nist_data.py
│   ├── test_large_hash.py
│   └── test_openssl.ps1
│
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── csprng.py
│       ├── digest.py
│       ├── file_io.py
│       │
│       ├── hashes/
│       │   ├── __init__.py
│       │   ├── sha256.py
│       │   └── sha3_256.py
│       │
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

# Файлы, которые не хранятся в репозитории

В Git не добавляются:

```text
.venv/
.idea/
__pycache__/
.pytest_cache/
*.egg-info/

nist_test_data.bin
large_hash_test.bin

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

hash_test.txt
sprint4.txt
sprint4.sha256
weak.bin
```

Эти файлы являются временными результатами тестов или локальными служебными файлами.

# Версия проекта

Текущая версия:

```text
0.4.0
```

# Финальная проверка

Перед отправкой изменений в GitHub выполняем:

```powershell
pytest -q
```

Затем при необходимости проверяем совместимость AES:

```powershell
.\scripts\test_openssl.ps1
```

SHA-256:

```bash
sha256sum hash_test.txt
```

SHA3-256:

```bash
openssl dgst -sha3-256 hash_test.txt
```

Для отдельной ручной проверки больших файлов подготовлена команда:

```powershell
python scripts\test_large_hash.py --size-gb 1
```

Таким образом, проект сохраняет функциональность Sprint 1–3 и добавляет полноценную поддержку криптографического хеширования в Sprint 4.