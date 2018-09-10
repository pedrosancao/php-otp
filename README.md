# A PHP One-Time Password implementation

This small library implements the HMAC-based one-time password algorithms
used mostly on two steps authentication: time based TOTP
([RFC 6238](https://tools.ietf.org/html/rfc6238)) and HOTP
([RFC 4226](https://tools.ietf.org/html/rfc4226)).

Easily and quick allows to configure and use mobile apps like Google Authenticator.

## Requirements

php >= 5.4

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
$totp = PedroSancao\OTP\TOTP::createRaw($base32encodedSecret);
echo $totp->getPassword();
```

## To do list

- Creation from URI
- Unit tests

## Licence

This library is release under the [MIT licence](LICENCE).