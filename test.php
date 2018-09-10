<?php

require_once dirname(__FILE__) . '/vendor/autoload.php';

/**
 * RFC 6232
 * Appendix B. Test Vectors
 */
$totp = \PedroSancao\OTP\TOTP::createRaw('12345678901234567890', 8);
var_dump($totp->verify('94287082', 59, 1));
var_dump($totp->verify('07081804', 1111111109, 1));
var_dump($totp->verify('14050471', 1111111111, 1));
var_dump($totp->verify('89005924', 1234567890, 1));
var_dump($totp->verify('69279037', 2000000000, 1));
var_dump($totp->verify('65353130', 20000000000, 1));
