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
- возможность передачи IV через CLI при расшифровании;
- проверку корректности IV;
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
- тест генерации 1000 уникальных ключей;
- базовую статистическую проверку распределения битов;
- подготовку бинарных данных для NIST STS;
- проверку CSPRNG через NIST Statistical Test Suite.

# Требования

Для запуска проекта нам понадобятся:

- Python 3.10 или новее;
- PyCryptodome;
- pytest.

Для проверки совместимости с внешней реализацией AES используется OpenSSL.

Для статистического анализа CSPRNG использовался NIST Statistical Test Suite.

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

Также программу можно запускать через Python:

```powershell
python -m cryptocore --help
```

# Формат CLI

Основной формат команды:

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

В проекте используется AES со 128-битным ключом.

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

В режиме ECB используется PKCS#7 padding.

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

Сравним хэши исходного и расшифрованного файлов:

```powershell
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash decrypted.txt).Hash
```

Ожидаемый результат:

```text
True
```

## Проверка ECB через OpenSSL

Зашифруем файл через CryptoCore:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cryptocore_ecb.bin
```

Зашифруем тот же файл через OpenSSL:

```powershell
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -nosalt -in plaintext.txt -out openssl_ecb.bin
```

Сравним хэши:

```powershell
(Get-FileHash cryptocore_ecb.bin).Hash -eq (Get-FileHash openssl_ecb.bin).Hash
```

При совпадении реализаций получаем:

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

CFB используется с размером сегмента 128 бит и не требует padding.

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

Для CBC, CFB, OFB и CTR используется IV длиной 16 байт.

При шифровании IV генерируется автоматически через общий CSPRNG.

Формат выходного файла:

```text
<16-byte IV><ciphertext>
```

При обычном расшифровании CryptoCore автоматически читает первые 16 байт входного файла как IV.

Например:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

Также IV можно передать вручную:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input ciphertext.bin --output decrypted.txt
```

Если используется `--iv`, входной файл должен содержать непосредственно ciphertext без IV в начале.

# Проверка совместимости Sprint 2 с OpenSSL

Для режимов:

```text
CBC
CFB
OFB
CTR
```

мы проверяем совместимость в двух направлениях:

```text
CryptoCore -> OpenSSL
OpenSSL -> CryptoCore
```

Для автоматической проверки используется скрипт:

```text
scripts/test_openssl.ps1
```

Запуск:

```powershell
.\scripts\test_openssl.ps1
```

Успешное выполнение подтверждает, что данные, зашифрованные CryptoCore, корректно расшифровываются OpenSSL, а данные, зашифрованные OpenSSL, корректно расшифровываются CryptoCore.

# Sprint 3

## CSPRNG

Для генерации криптографически стойких случайных данных используется отдельный модуль:

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

Модуль `random` для генерации ключей и IV мы не используем.

Если системный источник случайности завершится с ошибкой, модуль CSPRNG преобразует её в контролируемую ошибку приложения.

# Автоматическая генерация ключа

При шифровании параметр `--key` необязателен.

Например:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --input plaintext.txt --output ciphertext.bin
```

Если ключ не передан, CryptoCore автоматически создаёт случайный ключ AES-128 и один раз выводит его в терминал:

```text
[INFO] Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```

После этого программа продолжает шифрование с новым ключом.

Сгенерированный ключ не записывается в ciphertext.

Его необходимо сохранить отдельно для последующего расшифрования.

# Расшифрование

При расшифровании ключ обязателен.

Например:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 1a2b3c4d5e6f7890fedcba9876543210 --input ciphertext.bin --output decrypted.txt
```

Если при расшифровании `--key` отсутствует, программа завершится с ошибкой.

# Предупреждение о потенциально слабом ключе

Для вручную переданного ключа выполняется дополнительная эвристическая проверка.

Например:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 00000000000000000000000000000000 --input plaintext.txt --output weak.bin
```

Если ключ соответствует одной из проверяемых слабых структур, программа продолжает работу, но выводит предупреждение в `stderr`:

```text
[WARNING] Provided key appears weak.
```

Это предупреждение не заменяет криптографический анализ ключа и используется как дополнительная проверка ввода.

# Тестирование CSPRNG

Для CSPRNG выполняется автоматический тест генерации:

```text
1000 ключей
16 байт каждый
```

Проверяется, что среди 1000 полученных ключей нет повторений.

Также выполняется базовая статистическая проверка распределения битов с использованием веса Хэмминга.

Для сгенерированного набора данных вычисляется доля единичных битов. В тесте допускается диапазон, близкий к 50%.

Дополнительно проверяются:

- корректная длина случайной последовательности;
- обработка отрицательного размера;
- обработка некорректного типа аргумента;
- обработка ошибки `os.urandom()`.

# Подготовка данных для NIST STS

Для генерации большого бинарного файла используется:

```text
scripts/generate_nist_data.py
```

Например:

```powershell
python scripts\generate_nist_data.py --size-mb 13
```

В результате создаётся файл:

```text
nist_test_data.bin
```

Этот файл используется только как входной набор данных для статистической проверки и не хранится в GitHub.

# NIST Statistical Test Suite

Для дополнительной статистической проверки CSPRNG был использован NIST Statistical Test Suite.

Тестовые данные были получены напрямую с помощью:

```python
generate_random_bytes()
```

Для проверки использовались следующие параметры:

```text
100 последовательностей
1 000 000 бит в каждой последовательности
Binary input
Все 15 статистических тестов NIST STS
```

Запуск NIST STS выполнялся командой:

```bash
./assess.exe 1000000
```

Были запущены следующие тесты:

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

Для основных статистических тестов итоговый отчёт NIST STS указал минимальную допустимую долю прохождения приблизительно:

```text
96/100
```

Для Random Excursions / Random Excursions Variant минимальная доля прохождения составила приблизительно:

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

В полном отчёте были зафиксированы отдельные значения uniformity `P-VALUE` ниже `0.01`:

```text
NonOverlappingTemplate
P-VALUE = 0.003201
PROPORTION = 99/100

Serial
P-VALUE = 0.001112
PROPORTION = 100/100
```

Эти отдельные статистические отклонения не сопровождались массовыми отказами последовательностей.

В целом полный прогон NIST STS не показал массовых статистических провалов генерируемых данных.

Полный итоговый отчёт сохранён в:

```text
docs/nist_final_report.txt
```

# Автоматические тесты

Для запуска всех автоматических тестов проекта:

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
- корректность ключей;
- корректность IV;
- CLI;
- работу с бинарными файлами;
- полный цикл encrypt -> decrypt;
- автоматическую генерацию ключа;
- обязательность ключа при расшифровании;
- предупреждение о потенциально слабом ключе;
- CSPRNG;
- генерацию 1000 уникальных ключей;
- базовое распределение битов;
- обработку ошибки источника случайности;
- совместимость с функциональностью предыдущих спринтов.

# Обработка ошибок

CryptoCore проверяет:

- обязательные CLI-параметры;
- поддерживаемый алгоритм;
- поддерживаемый режим;
- длину AES-128 ключа;
- формат HEX-ключа;
- длину IV;
- формат HEX-IV;
- наличие входного файла;
- корректность PKCS#7 padding;
- минимальный размер файла для извлечения IV;
- обязательность ключа при расшифровании;
- ошибки CSPRNG.

При ошибке программа выводит диагностическое сообщение и завершается с ненулевым кодом возврата.

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

# Файлы, которые не хранятся в репозитории

В репозиторий не добавляются:

- виртуальное окружение `.venv`;
- настройки IDE `.idea`;
- Python cache;
- pytest cache;
- build-файлы;
- временные файлы шифрования и расшифрования;
- бинарный файл `nist_test_data.bin`;
- результаты временных ручных проверок OpenSSL;
- установленная копия NIST Statistical Test Suite.

Все необходимые тестовые данные можно создать повторно с помощью предоставленных скриптов.

# Версия проекта

Текущая версия:

```text
0.3.0
```

# Финальная проверка

Перед отправкой изменений в репозиторий запускаем все автоматические тесты:

```powershell
pytest -q
```

Затем проверяем совместимость с OpenSSL:

```powershell
.\scripts\test_openssl.ps1
```

Для Sprint 3 дополнительно был выполнен полный прогон NIST Statistical Test Suite.

Итоговый отчёт доступен в:

```text
docs/nist_final_report.txt
```

Таким образом, функциональность Sprint 1, Sprint 2 и Sprint 3 сохраняется и проверяется совместно.