<?php

namespace Tests;

use PedroSancao\OTP\TOTP;
use PHPUnit\Framework\TestCase;

/**
 * Test on values provided on RFC 6238.
 *
 * @see https://tools.ietf.org/html/rfc6238#appendix-B
 */
final class Rfc6238VectorTest extends TestCase
{
    /** @test */
    public function is_should_generate_correct_passwords_using_sha1()
    {
        $totp = TOTP::createRaw('12345678901234567890', 8)->useSha1();
        $this->assertTrue($totp->verify('94287082', 59, 1));
        $this->assertTrue($totp->verify('07081804', 1111111109, 1));
        $this->assertTrue($totp->verify('14050471', 1111111111, 1));
        $this->assertTrue($totp->verify('89005924', 1234567890, 1));
        $this->assertTrue($totp->verify('69279037', 2000000000, 1));
        $this->assertTrue($totp->verify('65353130', 20000000000, 1));
    }

    /** @test */
    public function is_should_generate_correct_passwords_using_sha256()
    {
        $totp = TOTP::createRaw('12345678901234567890123456789012', 8)->useSha256();
        $this->assertTrue($totp->verify('46119246', 59, 1));
        $this->assertTrue($totp->verify('68084774', 1111111109, 1));
        $this->assertTrue($totp->verify('67062674', 1111111111, 1));
        $this->assertTrue($totp->verify('91819424', 1234567890, 1));
        $this->assertTrue($totp->verify('90698825', 2000000000, 1));
        $this->assertTrue($totp->verify('77737706', 20000000000, 1));
    }

    /** @test */
    public function is_should_generate_correct_passwords_using_sha512()
    {
        $totp = TOTP::createRaw('1234567890123456789012345678901234567890123456789012345678901234', 8)->useSha512();
        $this->assertTrue($totp->verify('90693936', 59, 1));
        $this->assertTrue($totp->verify('25091201', 1111111109, 1));
        $this->assertTrue($totp->verify('99943326', 1111111111, 1));
        $this->assertTrue($totp->verify('93441116', 1234567890, 1));
        $this->assertTrue($totp->verify('38618901', 2000000000, 1));
        $this->assertTrue($totp->verify('47863826', 20000000000, 1));
    }
}
