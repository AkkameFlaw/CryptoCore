$ErrorActionPreference = "Stop"

$key = "000102030405060708090a0b0c0d0e0f"
$fixedIv = "aabbccddeeff00112233445566778899"
$modes = @("cbc", "cfb", "ofb", "ctr")

Set-Content -NoNewline -Path plaintext.txt -Value "CryptoCore OpenSSL compatibility test"

foreach ($mode in $modes) {
    Write-Host "Testing $mode..."

    $cryptoFile = "crypto_$mode.bin"
    $cipherOnly = "cipher_$mode.bin"
    $opensslDecrypted = "openssl_$mode.txt"

    cryptocore --algorithm aes --mode $mode --encrypt --key $key --input plaintext.txt --output $cryptoFile

    if ($LASTEXITCODE -ne 0) {
        throw "CryptoCore encryption failed for $mode"
    }

    $data = [System.IO.File]::ReadAllBytes($cryptoFile)

    $iv = $data[0..15]
    $cipher = $data[16..($data.Length - 1)]

    [System.IO.File]::WriteAllBytes(
        $cipherOnly,
        $cipher
    )

    $ivHex = -join (
        $iv |
        ForEach-Object {
            $_.ToString("x2")
        }
    )

    openssl enc "-aes-128-$mode" -d -K $key -iv $ivHex -in $cipherOnly -out $opensslDecrypted

    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL decryption failed for $mode"
    }

    $originalHash = (
        Get-FileHash plaintext.txt
    ).Hash

    $decryptedHash = (
        Get-FileHash $opensslDecrypted
    ).Hash

    if ($originalHash -ne $decryptedHash) {
        throw "CryptoCore -> OpenSSL failed for $mode"
    }

    $opensslCipher = "openssl_cipher_$mode.bin"
    $cryptoDecrypted = "crypto_decrypted_$mode.txt"

    openssl enc "-aes-128-$mode" -K $key -iv $fixedIv -in plaintext.txt -out $opensslCipher

    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL encryption failed for $mode"
    }

    cryptocore --algorithm aes --mode $mode --decrypt --key $key --iv $fixedIv --input $opensslCipher --output $cryptoDecrypted

    if ($LASTEXITCODE -ne 0) {
        throw "CryptoCore decryption failed for $mode"
    }

    $decryptedHash = (
        Get-FileHash $cryptoDecrypted
    ).Hash

    if ($originalHash -ne $decryptedHash) {
        throw "OpenSSL -> CryptoCore failed for $mode"
    }

    Write-Host "$mode OK"
}

Write-Host "All OpenSSL compatibility tests passed."