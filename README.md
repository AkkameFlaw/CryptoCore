# CryptoCore

CryptoCore — консольный инструмент для шифрования и расшифрования файлов с использованием AES-128.

Проект развивается по спринтам. Каждый следующий спринт расширяет существующую реализацию и сохраняет функциональность предыдущих этапов.

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
- проверку полного цикла encrypt -> decrypt;
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
- тесты новых режимов;
- проверку совместимости с PyCryptodome;
- проверку совместимости с OpenSSL в обе стороны.

## Sprint 3

В третьем спринте мы добавили:

- отдельный модуль CSPRNG;
- функцию `generate_random_bytes(num_bytes)`;
- использование `os.urandom()` как криптографически стойкого источника случайности;
- автоматическую генерацию AES-128 ключа при шифровании без `--key`;
- вывод сгенерированного ключа в терминал;
- обязательный `--key` при расшифровании;
- генерацию IV через общий модуль CSPRNG;
- предупреждение о потенциально слабых ключах;
- тест 1000 уникальных случайных ключей;
- базовую статистическую проверку распределения;
- подготовку бинарных данных для NIST STS;
- проверку CSPRNG через NIST Statistical Test Suite.

# Требования

Для запуска проекта нам понадобятся:

- Python 3.10 или новее;
- pycryptodome;
- pytest.

Для проверки совместимости мы используем OpenSSL.

Для статистического анализа CSPRNG мы использовали NIST Statistical Test Suite.

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

Также мы можем запускать программу через Python:

```powershell
python -m cryptocore --help
```

# Формат CLI

Основной формат:

```text
cryptocore --algorithm aes --mode MODE --encrypt|--decrypt [--key KEY] --input INPUT [--output OUTPUT] [--iv IV]
```

Поддерживаемые режимы:

```text
ecb
cbc
cfb
ofb
ctr
```

# AES-128

Мы используем AES со 128-битным ключом.

Если ключ передаётся вручную, он задаётся как HEX-строка длиной 32 символа:

```text
000102030405060708090a0b0c0d0e0f
```

# Sprint 1

## ECB

Для шифрования:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Для расшифрования:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

В ECB мы используем PKCS#7 padding.

## Проверка полного цикла Sprint 1

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

Получаем:

```text
True
```

## Проверка ECB через OpenSSL

Зашифруем через CryptoCore:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cryptocore_ecb.bin
```

Зашифруем тот же файл через OpenSSL:

```powershell
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -nosalt -in plaintext.txt -out openssl_ecb.bin
```

Сравним:

```powershell
(Get-FileHash cryptocore_ecb.bin).Hash -eq (Get-FileHash openssl_ecb.bin).Hash
```

Результат:

```text
True
```

# Sprint 2

## CBC

Шифрование:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cbc.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

CBC использует PKCS#7 padding.

## CFB

Шифрование:

```powershell
cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cfb.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cfb.bin --output decrypted.txt
```

CFB использует полный сегмент размером 128 бит и не требует padding.

## OFB

Шифрование:

```powershell
cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ofb.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ofb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ofb.bin --output decrypted.txt
```

OFB не использует padding.

## CTR

Шифрование:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ctr.bin
```

Расшифрование:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --input ctr.bin --output decrypted.txt
```

CTR не использует padding.

# Работа с IV

Для CBC, CFB, OFB и CTR мы используем IV длиной 16 байт.

При шифровании IV генерируется автоматически через общий CSPRNG.

Формат выходного файла:

```text
<16-byte IV><ciphertext>
```

При обычном расшифровании CryptoCore автоматически читает первые 16 байт файла как IV.

Например:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

Также мы можем передать IV вручную:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input ciphertext.bin --output decrypted.txt
```

Если мы используем `--iv`, входной файл должен содержать непосредственно ciphertext без IV в начале.

# Проверка совместимости Sprint 2 с OpenSSL

Мы проверили два направления:

```text
CryptoCore -> OpenSSL
OpenSSL -> CryptoCore
```

для:

```text
CBC
CFB
OFB
CTR
```

Для автоматической проверки используется:

```text
scripts/test_openssl.ps1
```

Запуск:

```powershell
.\scripts\test_openssl.ps1
```

При успешной проверке мы получаем:

```text
Testing cbc...
cbc OK
Testing cfb...
cfb OK
Testing ofb...
ofb OK
Testing ctr...
ctr OK
All OpenSSL compatibility tests passed.
```

# Sprint 3

## CSPRNG

Для генерации криптографически стойких случайных данных мы используем отдельный модуль:

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

Мы не используем модуль `random` для генерации криптографических ключей или IV.

# Автоматическая генерация ключа

При шифровании параметр `--key` теперь необязателен.

Например:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

CryptoCore создаст случайный ключ AES-128 и выведет его в терминал:

```text
[INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```

После этого программа продолжит шифрование с этим ключом.

Сгенерированный ключ не записывается в ciphertext.

Пользователь должен самостоятельно сохранить его для последующего расшифрования.

# Расшифрование

При расшифровании ключ остаётся обязательным.

Например:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 1a2b3c4d5e6f7890fedcba9876543210 --input ciphertext.bin --output decrypted.txt
```

Если `--key` отсутствует, программа завершится с ошибкой.

# Предупреждение о слабом ключе

Если пользователь передаёт потенциально слабый ключ, CryptoCore выводит предупреждение в `stderr`.

Например:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 00000000000000000000000000000000 --input plaintext.txt --output weak.bin
```

Программа продолжит работу, но выведет:

```text
[WARNING] Provided key appears weak.
```

# Тестирование CSPRNG

Мы выполняем тест генерации 1000 ключей:

```text
1000 ключей
16 байт каждый
```

Тест проверяет отсутствие дубликатов.

Также выполняется базовая проверка распределения битов через вес Хэмминга.

Ожидаемая доля единичных битов находится примерно около 50%.

# Подготовка данных для NIST STS

Для генерации большого бинарного файла используется:

```text
scripts/generate_nist_data.py
```

Например:

```powershell
python scripts\generate_nist_data.py --size-mb 13
```

В результате создаётся:

```text
nist_test_data.bin
```

Этот файл используется только для статистической проверки и не хранится в GitHub.

# NIST Statistical Test Suite

Для статистической проверки CSPRNG мы использовали NIST Statistical Test Suite.

Тестовые данные были получены напрямую из:

```python
generate_random_bytes()
```

Для тестирования мы использовали:

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

Мы выполнили:

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

Для основных тестов NIST STS указал минимально допустимую долю прохождения:

```text
96/100
```

Для Random Excursions и Random Excursions Variant:

```text
61/65
```

Полученные значения `PROPORTION` соответствуют этим порогам.

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

Для Random Excursions и Random Excursions Variant результаты составили преимущественно:

```text
64/65
65/65
```

В отчёте были зафиксированы отдельные значения uniformity `P-VALUE` ниже `0.01`:

```text
NonOverlappingTemplate
P-VALUE = 0.003201
PROPORTION = 99/100

Serial
P-VALUE = 0.001112
PROPORTION = 100/100
```

Эти единичные статистические отклонения не сопровождаются массовыми отказами последовательностей.

По результатам полного тестирования CSPRNG не показывает массовых статистических провалов.

Полный отчёт NIST STS сохранён в:

```text
docs/nist_final_report.txt
```

# Автоматические тесты

Для запуска всех тестов проекта:

```powershell
pytest -q
```

Тесты проверяют:

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
- работу с бинарными файлами;
- полный цикл encrypt -> decrypt;
- автоматическую генерацию ключа;
- обязательность ключа при расшифровании;
- предупреждение о слабом ключе;
- CSPRNG;
- генерацию 1000 уникальных ключей;
- базовое распределение битов;
- обработку ошибки источника случайности;
- совместимость с предыдущими спринтами.

# Обработка ошибок

CryptoCore проверяет:

- обязательные CLI-параметры;
- алгоритм;
- режим;
- ключ AES-128;
- IV;
- наличие входного файла;
- корректность PKCS#7;
- минимальный размер входного файла для извлечения IV;
- обязательность ключа при расшифровании;
- ошибки CSPRNG.

При ошибке программа выводит сообщение в `stderr` и завершается с ненулевым кодом возврата.

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
│   └── test_openssl.ps1
│
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── csprng.py
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
    ├── test_ecb.py
    └── test_modes.py
```

# Версия проекта

Текущая версия:

```text
0.3.0
```

# Финальная проверка

Перед загрузкой изменений в GitHub мы запускаем:

```powershell
pytest -q
```

Затем проверяем совместимость Sprint 2:

```powershell
.\scripts\test_openssl.ps1
```

Также для Sprint 3 мы выполнили полный прогон NIST Statistical Test Suite и сохранили итоговый отчёт:

```text
docs/nist_final_report.txt
```

Таким образом, функциональность Sprint 1, Sprint 2 и Sprint 3 сохраняется и проверяется совместно.