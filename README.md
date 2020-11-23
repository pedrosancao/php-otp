# A PHP One-Time Password implementation

![project license](https://img.shields.io/github/license/pedrosancao/php-otp)
![code size](https://img.shields.io/github/languages/code-size/pedrosancao/php-otp)
![PHP version](https://img.shields.io/packagist/php-v/pedrosancao/php-otp)
![packagist version](https://img.shields.io/packagist/v/pedrosancao/php-otp)
![packagist downloads](https://img.shields.io/packagist/dt/pedrosancao/php-otp)
![test coverage](https://img.shields.io/codecov/c/github/pedrosancao/php-otp)
![tests status](https://img.shields.io/github/workflow/status/pedrosancao/php-otp/PHP%20Composer?label=tests)

This small library implements the HMAC-based one-time password algorithms
used mostly on two steps authentication: time based TOTP
([RFC 6238](https://tools.ietf.org/html/rfc6238)) and HOTP
([RFC 4226](https://tools.ietf.org/html/rfc4226)).

Easily and quick allows to configure and use mobile apps like Google Authenticator.

## Requirements

Although it should work even on PHP 5.4. We strongly recommend using PHP >= 7.3 as
lower versions have [reached end of life](https://www.php.net/supported-versions.php).

## Installation

Preferable use composer

```sh
composer require pedrosancao/php-otp
```

## Usage

### Syncing time-based one-time password with client

Create a new token

```php
$totp = PedroSancao\OTP\TOTP::create();
```

Present URI to user as a QR-Code or show base 32 encoded secret

```php
// example using Google API, it's recommended to use a local library
$uri = $totp->getUri('user@domain.com', 'Issuer Name');
$src = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . urlencode($uri);
printf('<img src="%s"/>', $src);
// OR
echo $totp->getSecretReadable();
```

Store the shared secret

```php
$secret = $totp->getRawSecret();
```

### Verifying passwords

```php
$totp = PedroSancao\OTP\TOTP::createRaw($storedSecret);
$totp->verify($inputPassword);
```

### Using as client

```php
$totp = PedroSancao\OTP\TOTP::create($base32encodedSecret);
// or
$totp = PedroSancao\OTP\TOTP::createRaw($storedSecret);
// or
$totp = PedroSancao\OTP\TOTP::createFromURI($uriFromQrCode);
echo $totp->getPassword();
```

### Change hashing algorithm

SHA1 is the default method. If you want to use another after create a new instance
with one of `create*` methods call `useSha256` or `useSha512`: 

```php
$totp = PedroSancao\OTP\TOTP::createRaw($storedSecret)->useSha256();
```

## To do list

- Implement [all URI parameters](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)

## Licence

This library is release under the [MIT licence](LICENCE).
