# CryptoCore

CryptoCore — консольный инструмент для шифрования и расшифрования файлов с использованием AES-128.

В проекте мы постепенно реализуем различные режимы работы AES и расширяем функциональность по спринтам.

---

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
- проверку полного цикла шифрования и расшифрования;
- проверку совместимости ECB с OpenSSL.

## Sprint 2

Во втором спринте мы расширили существующий проект и добавили:

- CBC;
- CFB;
- OFB;
- CTR;
- автоматическую генерацию IV;
- хранение IV в начале зашифрованного файла;
- возможность передавать IV через CLI при расшифровании;
- проверку корректности IV;
- тесты новых режимов;
- проверку совместимости с PyCryptodome;
- проверку совместимости с OpenSSL в обе стороны.

---

# Требования

Для запуска проекта нам понадобятся:

- Python 3.10 или новее;
- pycryptodome;
- pytest.

Для проверки совместимости мы также используем OpenSSL.

---

# Установка

Сначала создадим виртуальное окружение:

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

---

# Проверка установки

Проверим работу CLI:

```powershell
cryptocore --help
```

Также мы можем запускать программу через Python:

```powershell
python -m cryptocore --help
```

---

# Формат CLI

Основной формат команды:

```text
cryptocore --algorithm aes --mode MODE --encrypt|--decrypt --key KEY --input INPUT [--output OUTPUT] [--iv IV]
```

Поддерживаемые режимы:

```text
ecb
cbc
cfb
ofb
ctr
```

---

# Ключ AES-128

Для AES-128 мы используем ключ длиной 16 байт.

Через CLI передаём его в виде HEX-строки длиной 32 символа.

Например:

```text
000102030405060708090a0b0c0d0e0f
```

---

# Sprint 1

## ECB

В первом спринте мы реализовали режим ECB.

Для шифрования выполним:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Для расшифрования:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

В режиме ECB мы используем PKCS#7 padding.

## Проверка Sprint 1

Создадим тестовый файл:

```powershell
Set-Content -NoNewline -Path plaintext.txt -Value "CryptoCore Sprint 1 test"
```

Зашифруем его:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифруем:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Сравним исходный и расшифрованный файлы:

```powershell
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash decrypted.txt).Hash
```

При корректной работе получим:

```text
True
```

---

# Проверка ECB через OpenSSL

Для дополнительной проверки мы сравним результат CryptoCore с OpenSSL.

Сначала зашифруем файл через CryptoCore:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cryptocore_ecb.bin
```

Теперь зашифруем тот же файл через OpenSSL:

```powershell
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -nosalt -in plaintext.txt -out openssl_ecb.bin
```

Сравним результаты:

```powershell
(Get-FileHash cryptocore_ecb.bin).Hash -eq (Get-FileHash openssl_ecb.bin).Hash
```

При проверке мы получили:

```text
True
```

Это подтверждает совместимость нашей реализации ECB с OpenSSL.

---

# Sprint 2

Во втором спринте мы добавили четыре новых режима:

```text
CBC
CFB
OFB
CTR
```

---

# CBC

Для шифрования в режиме CBC выполним:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cbc.bin
```

Для расшифрования:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

В режиме CBC мы используем PKCS#7 padding.

---

# CFB

Для шифрования:

```powershell
cryptocore --algorithm aes --mode cfb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cfb.bin
```

Для расшифрования:

```powershell
cryptocore --algorithm aes --mode cfb --decrypt --key 000102030405060708090a0b0c0d0e0f --input cfb.bin --output decrypted.txt
```

В режиме CFB мы используем полный сегмент размером 128 бит.

Padding в этом режиме нам не нужен.

---

# OFB

Для шифрования:

```powershell
cryptocore --algorithm aes --mode ofb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ofb.bin
```

Для расшифрования:

```powershell
cryptocore --algorithm aes --mode ofb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ofb.bin --output decrypted.txt
```

Padding для OFB мы не используем.

---

# CTR

Для шифрования:

```powershell
cryptocore --algorithm aes --mode ctr --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ctr.bin
```

Для расшифрования:

```powershell
cryptocore --algorithm aes --mode ctr --decrypt --key 000102030405060708090a0b0c0d0e0f --input ctr.bin --output decrypted.txt
```

Padding для CTR мы также не используем.

---

# Работа с IV

Для режимов:

```text
CBC
CFB
OFB
CTR
```

мы используем IV длиной 16 байт.

При шифровании мы не передаём IV вручную.

CryptoCore автоматически генерирует его с помощью:

```python
os.urandom(16)
```

После генерации мы записываем IV в начало выходного файла.

Формат файла:

```text
<16-byte IV><ciphertext>
```

Таким образом:

```text
первые 16 байт = IV
остальные байты = ciphertext
```

При обычном расшифровании нам не нужно передавать IV отдельно.

CryptoCore автоматически прочитает первые 16 байт входного файла.

Например:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

При необходимости мы можем передать IV вручную:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input ciphertext.bin --output decrypted.txt
```

Если мы передаём `--iv` вручную, входной файл должен содержать непосредственно ciphertext без IV в начале файла.

При шифровании использовать `--iv` нельзя, поскольку IV генерируется автоматически.

---

# Автоматические тесты

Для запуска всех тестов выполним:

```powershell
pytest -q
```

С помощью тестов мы проверяем:

- AES-128;
- ECB;
- CBC;
- CFB;
- OFB;
- CTR;
- PKCS#7 padding;
- корректность ключа;
- корректность IV;
- работу с текстовыми файлами;
- работу с бинарными файлами;
- обработку неполного последнего блока;
- полный цикл encrypt -> decrypt;
- неправильные аргументы CLI;
- отсутствие входного файла;
- совместимость реализации режимов с PyCryptodome.

При успешном прохождении тестов pytest не должен выводить:

```text
FAILED
ERROR
```

---

# Проверка полного цикла Sprint 2

Создадим тестовый файл:

```powershell
Set-Content -NoNewline -Path plaintext.txt -Value "CryptoCore Sprint 2 test"
```

Например, проверим CBC.

Зашифруем:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cbc.bin
```

Расшифруем:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input cbc.bin --output decrypted.txt
```

Сравним файлы:

```powershell
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash decrypted.txt).Hash
```

При корректной работе получим:

```text
True
```

Таким же способом мы можем проверить:

```text
CFB
OFB
CTR
```

---

# Совместимость с OpenSSL

Во втором спринте мы проверяем совместимость CryptoCore с OpenSSL.

Проверим установленную версию:

```powershell
openssl version
```

Мы проверяем два направления:

```text
CryptoCore -> OpenSSL
OpenSSL -> CryptoCore
```

для всех новых режимов:

```text
CBC
CFB
OFB
CTR
```

---

# Автоматическая проверка OpenSSL

Для автоматической проверки мы используем:

```text
scripts/test_openssl.ps1
```

Запустим:

```powershell
.\scripts\test_openssl.ps1
```

Скрипт проверяет:

```text
CBC: CryptoCore -> OpenSSL
CBC: OpenSSL -> CryptoCore

CFB: CryptoCore -> OpenSSL
CFB: OpenSSL -> CryptoCore

OFB: CryptoCore -> OpenSSL
OFB: OpenSSL -> CryptoCore

CTR: CryptoCore -> OpenSSL
CTR: OpenSSL -> CryptoCore
```

При успешном выполнении мы получим:

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

---

# Ручная проверка CryptoCore -> OpenSSL

Создадим тестовый файл:

```powershell
Set-Content -NoNewline -Path plaintext.txt -Value "CryptoCore Sprint 2 OpenSSL test"
```

Зашифруем через CryptoCore:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output cbc.bin
```

Отделим IV от ciphertext:

```powershell
$data = [System.IO.File]::ReadAllBytes("cbc.bin")
$iv = $data[0..15]
$cipher = $data[16..($data.Length - 1)]
[System.IO.File]::WriteAllBytes("cipher_only.bin", $cipher)
$ivHex = -join ($iv | ForEach-Object { $_.ToString("x2") })
$ivHex
```

Расшифруем через OpenSSL:

```powershell
openssl enc -aes-128-cbc -d -K 000102030405060708090a0b0c0d0e0f -iv $ivHex -in cipher_only.bin -out openssl_decrypted.txt
```

Сравним результат:

```powershell
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash openssl_decrypted.txt).Hash
```

При успешной проверке получим:

```text
True
```

Для остальных режимов мы используем:

```text
-aes-128-cfb
-aes-128-ofb
-aes-128-ctr
```

---

# Ручная проверка OpenSSL -> CryptoCore

Будем использовать фиксированный IV:

```text
aabbccddeeff00112233445566778899
```

Сначала зашифруем файл через OpenSSL:

```powershell
openssl enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv aabbccddeeff00112233445566778899 -in plaintext.txt -out openssl_cipher.bin
```

Теперь расшифруем через CryptoCore:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv aabbccddeeff00112233445566778899 --input openssl_cipher.bin --output cryptocore_decrypted.txt
```

Сравним результат:

```powershell
(Get-FileHash plaintext.txt).Hash -eq (Get-FileHash cryptocore_decrypted.txt).Hash
```

При успешной проверке получим:

```text
True
```

Аналогично мы проверяем:

```text
CBC
CFB
OFB
CTR
```

---

# Обработка ошибок

CryptoCore проверяет:

- наличие обязательных аргументов;
- корректность алгоритма;
- корректность режима;
- наличие ровно одного флага `--encrypt` или `--decrypt`;
- корректность AES-128 ключа;
- корректность IV;
- длину IV;
- наличие входного файла;
- корректность PKCS#7;
- минимальный размер файла при извлечении IV.

При ошибке программа выводит сообщение в `stderr` и завершается с ненулевым кодом возврата.

---

# Структура проекта

```text
CryptoCore/
├── .gitignore
├── README.md
├── pyproject.toml
├── requirements.txt
│
├── scripts/
│   └── test_openssl.ps1
│
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── file_io.py
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
    ├── test_ecb.py
    └── test_modes.py
```

---

# Версия проекта

Текущая версия:

```text
0.2.0
```

---

# Финальная проверка

Перед загрузкой изменений в GitHub мы выполним:

```powershell
pytest -q
```

После этого проверим совместимость с OpenSSL:

```powershell
.\scripts\test_openssl.ps1
```

Для Sprint 1 мы также отдельно проверили совместимость ECB с OpenSSL и получили:

```text
True
```

Если автоматические тесты проходят, а OpenSSL-проверки завершаются успешно, мы считаем требования Sprint 1 и Sprint 2 выполненными.