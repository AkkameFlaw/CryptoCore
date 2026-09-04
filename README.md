# CryptoCore

CryptoCore — консольный инструмент для шифрования
и расшифрования файлов.

В Sprint 1 реализована поддержка:

- AES-128;
- режима ECB;
- PKCS#7 padding;
- текстовых и бинарных файлов;
- CLI-интерфейса;
- автоматических тестов.

## Требования

Для работы необходим:

- Python 3.10 или новее;
- pycryptodome;
- pytest для запуска тестов.

## Установка

Открой терминал в корне проекта.

Создай виртуальное окружение:

```powershell
python -m venv .venv
```

Активируй его:

```powershell
.\.venv\Scripts\Activate.ps1
```

Установи проект и зависимости:

```powershell
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

## Проверка установки

```powershell
cryptocore --help
```

Также программу можно запускать через Python:

```powershell
python -m cryptocore --help
```

## Шифрование

Пример:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

## Расшифрование

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Ключ AES-128 передаётся как HEX-строка длиной
32 символа, что соответствует 16 байтам.

Например:

```text
000102030405060708090a0b0c0d0e0f
```

## Выходной файл по умолчанию

Если при шифровании не передать:

```text
--output
```

будет создан файл:

```text
<имя входного файла>.enc
```

Например:

```text
data.txt.enc
```

При расшифровании:

```text
<имя входного файла>.dec
```

## Запуск тестов

```powershell
pytest -q
```

Тесты проверяют:

- корректность PKCS#7;
- AES-128 ECB;
- шифрование и расшифрование;
- работу с бинарными файлами;
- неправильный ключ;
- неправильный режим;
- неправильный алгоритм;
- отсутствие входного файла;
- CLI;
- полный цикл encrypt -> decrypt.

## Проверка полного цикла вручную

Создай тестовый файл:

```powershell
Set-Content -NoNewline plaintext.txt "CryptoCore test message"
```

Зашифруй:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

Расшифруй:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Сравни файлы:

```powershell
if ((Get-FileHash plaintext.txt).Hash -eq (Get-FileHash decrypted.txt).Hash) { "OK" } else { "ERROR" }
```

Если программа работает правильно:

```text
OK
```

## Структура проекта

```text
CryptoCore/
│
├── .gitignore
├── README.md
├── pyproject.toml
├── requirements.txt
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
│           └── ecb.py
│
└── tests/
    ├── test_cli.py
    └── test_ecb.py
```

## Реализация ECB

Для криптографического примитива AES используется
библиотека `pycryptodome`.

Разбиение данных на блоки размером 16 байт,
обработка каждого блока и PKCS#7 padding
реализованы в проекте самостоятельно.

## Важно

Режим ECB используется в CryptoCore Sprint 1
в учебных целях в соответствии с техническим
заданием.