# php-aes-128-cbc-encryption

Author: Elie Koo
Created at: 1 Dec 2020

-Pass Data in json format
-Use HashKey and HashIV for AES encryption.
-HashIV key is 16 bytes.
-AES encryption strength setting mode is 128 bit (can be 256 bit), CipherMode:CBC, PaddingMode:PKCS7
-openssl_encrypt() already does PKCS#7 padding



Reference: openssl_encrypt() parameters https://www.php.net/manual/en/function.openssl-encrypt.php
----------------------------
```openssl_encrypt ( string $data , string $method , string $key [, int $options = 0 [, string $iv = "" [, string &$tag = NULL [, string $aad = "" [, int $tag_length = 16 ]]]]] ) : string|false
-------------------------------------
example:
$ciphertext_raw = openssl_encrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
```

Parameters
data
The plaintext message data to be encrypted.

method
The cipher method. For a list of available cipher methods, use openssl_get_cipher_methods().

key
The key.

options
options is a bitwise disjunction of the flags OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING.

iv
A non-NULL Initialization Vector.

tag
The authentication tag passed by reference when using AEAD cipher mode (GCM or CCM).

aad
Additional authentication data.

tag_length
The length of the authentication tag. Its value can be between 4 and 16 for GCM mode.