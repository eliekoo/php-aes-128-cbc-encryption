# php-aes-cbc-encryption

Author: Elie Koo

Created at: 1 Dec 2020


-Pass Data in json format

-Use SecretKey and SecretIV for AES encryption.

-SecretIV key is 16 bytes.

-AES encryption strength setting mode is 128 bit (can be 256 bit), CipherMode:CBC, PaddingMode:PKCS7

-openssl_encrypt() already does PKCS#7 padding



Reference: openssl_encrypt() parameters https://www.php.net/manual/en/function.openssl-encrypt.php

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

```
example:
$example_128 = openssl_encrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);


$example_256 = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);

```