# CryptoCore — руководство пользователя

Документ для CryptoCore 0.8.2. Проект является **учебным**. Для защиты реальных секретов не используйте его без независимого аудита.

## Установка

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Из корня проекта: `cryptocore --help`, `cryptocore dgst --help`, `cryptocore derive --help`. Для основной команды AES-128 ключ задаётся 32 HEX-символами (16 байт).

## Шифрование и расшифрование файлов

Создайте тестовый файл: PowerShell `Set-Content -NoNewline demo.txt "Hello CryptoCore"`; Bash `printf 'Hello CryptoCore' > demo.txt`.

Ключ во всех примерах **только тестовый**: `00112233445566778899aabbccddeeff`. Не копируйте его в реальные приложения.

| Режим | Шифрование | Расшифрование | Защита целостности |
|---|---|---|---|
| ECB | `--mode ecb` | `--mode ecb` | Нет |
| CBC | `--mode cbc` | `--mode cbc` | Нет |
| CFB | `--mode cfb` | `--mode cfb` | Нет |
| OFB | `--mode ofb` | `--mode ofb` | Нет |
| CTR | `--mode ctr` | `--mode ctr` | Нет |
| GCM | `--mode gcm` | `--mode gcm` | Да |
| EtM | `--mode etm` | `--mode etm` | Да |

Подставьте требуемый режим в команды:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input demo.txt --output demo.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input demo.bin --output result.txt
```

ECB использует PKCS#7; CBC использует PKCS#7; CFB/OFB/CTR — без padding. Для CBC/CFB/OFB/CTR файл содержит IV (16 байт) перед шифртекстом; не удаляйте его. Для GCM и EtM форматы другие — смотрите [API.md](API.md).

## AES-GCM и AAD

AAD (`--aad`) — **HEX-байты**, не обычный текст. Например, `metadata` в UTF-8 нужно предварительно перевести в HEX. Пример с `aabbcc`:

```powershell
cryptocore --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input demo.txt --output demo.gcm --aad aabbcc
cryptocore --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input demo.gcm --output restored.txt --aad aabbcc
```

Для больших AAD можно использовать `--aad-file metadata.bin` при шифровании и расшифровании GCM **и EtM**. Одновременно `--aad` и `--aad-file` указывать нельзя. При неверном AAD или изменении шифртекста ключ не будет расшифрован, выходной файл не перезаписывается. Никогда не повторяйте GCM nonce с тем же ключом.

## Encrypt-then-MAC

```powershell
cryptocore --algorithm aes --mode etm --encrypt --key 00112233445566778899aabbccddeeff --input demo.txt --output demo.etm --aad aabbcc
cryptocore --algorithm aes --mode etm --decrypt --key 00112233445566778899aabbccddeeff --input demo.etm --output restored.txt --aad aabbcc
```

Схема является внутренним учебным форматом и не обязательно совместима со сторонними EtM.

## SHA-256 и SHA3-256

```powershell
cryptocore dgst --algorithm sha256 --input demo.txt
cryptocore dgst --algorithm sha3-256 --input demo.txt
cryptocore dgst --algorithm sha256 --input demo.txt --output demo.sha256
```

Хеш вычисляется потоково. Простой хеш обнаруживает изменение только при доверенном исходном значении, но не подтверждает подлинность источника. Для подлинности используйте HMAC.

## HMAC-SHA256

```powershell
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input demo.txt --output demo.hmac
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input demo.txt --verify demo.hmac
```

## PBKDF2 derive

```powershell
cryptocore derive --password-prompt --salt 73616c74 --iterations 2 --length 32 --output demo.key
```

CLI выводит `KEY_HEX SALT_HEX` **с одним пробелом только с флагом `--show-key`**; иначе печатает только salt; файл `--output` содержит только бинарные байты ключа. `--salt` ожидает HEX; по умолчанию генерируется случайный salt из 16 байт. Значения по умолчанию: 100000 итераций, 32 байта. `--length`: 1..65536 байт.

Пароль можно прочитать из переменной окружения `--password-env NAME` или из бинарного файла `--password-file PATH`. Передача через `--password` может оставить пароль в истории терминала. Скрипт выводит производный секретный ключ в stdout; не направляйте его в открытые журналы. Изменяемые буферы очищаются best-effort, но Python не гарантирует удаление всех копий.

**Соль** можно хранить открыто, но при повторном получении ключа она и число итераций должны быть прежними. Используйте разные случайные соли; для реальной защиты паролей рассмотрите Argon2id и актуальные рекомендации, а не учебное фиксированное значение итераций.

## Устранение неполадок

| Симптом | Причина | Решение |
|---|---|---|
| `cryptocore` не найден | Не активировано venv или не выполнен editable install | Активируйте окружение, выполните `pip install -e ".[dev]"` |
| Некорректный `--key` | AES-128 требует 16 байт | 32 HEX-символа |
| Authentication failed | Неверный ключ/AAD либо повреждён payload | Используйте исходные параметры; не отключайте проверку тега |
| Неверный `--aad` | АAD должен быть HEX | Используйте `--aad-file` либо перекодируйте текст в HEX |
| `--salt must be ...` | Salt — чётная HEX-строка | Пример `73616c74` |
| `--length ... 65536` | Превышен лимит производного ключа | Уменьшите `--length` |
| Долго выполняется `derive` | Собственный Python HMAC-SHA256 | Для демонстраций используйте малое число итераций, но не для реальных паролей |
| `openssl` не найден на Windows | Программа не в PATH | `& "C:\msys64\ucrt64\bin\openssl.exe" version` |

## Краткая шпаргалка

```text
cryptocore --algorithm aes --mode MODE --encrypt --key HEX32 --input IN --output OUT
cryptocore --algorithm aes --mode MODE --decrypt --key HEX32 --input IN --output OUT
cryptocore dgst --algorithm sha256 --input IN
cryptocore dgst --algorithm sha3-256 --input IN
cryptocore dgst --algorithm sha256 --hmac --key HEX --input IN --verify MAC_FILE
cryptocore derive --password-prompt --salt HEX --iterations N --length BYTES --output KEY_FILE
```

## Сравнение с другими инструментами

OpenSSL предлагает оптимизированные хеши, PBKDF2 и режимы AES. `openssl enc` можно использовать для сравнения ECB/CBC/CFB/OFB/CTR, но **не** для прямой проверки GCM (`openssl enc -aes-128-gcm` не поддерживается). Для GCM в тестах применяется PyCryptodome как независимый эталон. GPG предоставляет готовые форматы сообщений и управление ключами; CryptoCore — учебная реализация, не замена GPG.

## Рекомендации

Предпочитайте GCM или EtM вместо неаутентифицированных режимов. Никогда не используйте один и тот же nonce/IV с одним ключом в потоковых режимах. Не храните секреты в Git и не печатайте ключи в публичных логах. Для важной информации используйте проверенную, поддерживаемую криптографическую библиотеку.


## Изменения защиты v0.8.1

Ввод пароля через `--password` разрешён только при явном `--allow-insecure-password-argv`. Предпочтительно `--password-prompt`, `--password-file` или `--password-env`. Для демонстрационного вывода полученного ключа нужно указать `--show-key`; без него `derive` требует `--output`. Количество итераций ограничено 100000 без флага `--allow-slow-kdf` (с ним не более 1000000).

При шифровании без `--key` CryptoCore создаёт файл `<output>.key` из 16 бинарных байтов вместо печати ключа. При расшифровании используйте `--key-file <output>.key`. Не добавляйте файлы ключей в репозиторий.

Локальный реестр `~/.cryptocore/nonces.sqlite3` блокирует повторный nonce/IV при одном ключе и не допускает шифрования, если он недоступен. Реестр нельзя удалять, переносить назад из резервной копии или независимо вести на нескольких устройствах с одним и тем же ключом.

Начиная с версии 0.8.1 большой основной файл шифруется и расшифровывается блоками по 64 КиБ. Результат публикуется через временный файл только после успешного завершения; GCM и EtM проверяют аутентификацию до публикации открытого текста. `--aad-file` работает и для GCM, и для EtM.

Рекомендуемые команды:

```powershell
cryptocore --algorithm aes --mode gcm --encrypt --input message.bin --output message.gcm
cryptocore --algorithm aes --mode gcm --decrypt --key-file message.gcm.key --input message.gcm --output restored.bin
cryptocore derive --password-prompt --iterations 100000 --output derived.key
```

Ограничения очистки памяти Python и нативного GCM описаны в `SECURITY_REVIEW_2026.md`.


## Обновление v0.8.2

Высокоуровневые библиотечные GCM/EtM и исторический `cryptocore.cli.encrypt_data` для CBC/CFB/OFB/CTR теперь используют **тот же локальный реестр nonce/IV**, что и файловый CLI. Низкоуровневые AES-примитивы, принимающие IV вручную, остаются образовательными и не защищены реестром. Рабочий библиотечный GCM использует нативный PyCryptodome, а Python-GHASH перенесён в учебный пример.

Для PBKDF2 безопаснее применять `derive --password-prompt --output derived.key`: новый файл ключа создаётся только если не существовал ранее. Если нужно получить ключ с другими параметрами, укажите **новое имя файла**, а не пытайтесь перезаписать старый.

**Для развертывания на нескольких устройствах не используйте один и тот же AES-ключ с разными несинхронизированными базами nonce.** Разделите ключи между устройствами или обеспечьте единое управление nonce в сервисе. Для реальных секретов учебный проект не рекомендуется.
