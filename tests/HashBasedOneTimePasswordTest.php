<?php

namespace Tests;

use PedroSancao\OTP\Exception;
use PedroSancao\OTP\HOTP;
use PHPUnit\Framework\TestCase;

final class HashBasedOneTimePasswordTest extends TestCase
{
    /** @test */
    public function it_should_create_a_instance()
    {
        $hotp = HOTP::create();
        $this->assertInstanceOf(HOTP::class, $hotp);
    }

    /** @test */
    public function it_should_create_a_instance_from_raw()
    {
        $hotp = HOTP::createRaw();
        $this->assertInstanceOf(HOTP::class, $hotp);
    }

    /** @test */
    public function it_should_create_a_instance_with_base32_data()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $rawData = "\x7a\x76\x73\x4b\x77\x6f\x52\x44\x72\x61\x4b\x61"
            . "\x6d\x78\x65\x49\x46\x78\x65\x66\x15\x4d\x6a\x55\xd2\x36"
            . "\x8d\x90\x99\xc2\x75\xae\x8a\x8f\x10\x22\xe0\x4d\x28\xdb";
        $hotp = HOTP::create($base32Data);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertEquals($rawData, $hotp->getRawSecret());
    }

    /** @test */
    public function it_should_create_a_instance_with_raw_data()
    {
        $rawData = "\x7a\x76\x73\x4b\x77\x6f\x52\x44\x72\x61\x4b\x61"
            . "\x6d\x78\x65\x49\x46\x78\x65\x66\x15\x4d\x6a\x55\xd2\x36"
            . "\x8d\x90\x99\xc2\x75\xae\x8a\x8f\x10\x22\xe0\x4d\x28\xdb";
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $hotp = HOTP::createRaw($rawData);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertEquals($base32Data, $hotp->getSecret());
    }

    /** @test */
    public function it_should_export_readable_code()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $readableData = 'PJ3H GS3X N5JE I4TB JNQW 26DF JFDH QZLG CVGW UVOS G2GZ BGOC OWXI VDYQ ELQE 2KG3';
        $hotp = HOTP::create($base32Data);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertEquals($readableData, $hotp->getSecretReadable());
    }

    /** @test */
    public function it_should_create_a_instance_from_uri()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $uri = "otpauth://hotp/PedroSancao:john.doe%40example.com?secret={$base32Data}&issuer=PedroSancao";
        $hotp = HOTP::createFromURI($uri);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertEquals($base32Data, $hotp->getSecret());
    }

    /** @test */
    public function it_should_export_uri()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $uri = "otpauth://hotp/PedroSancao:john.doe%40example.com?secret={$base32Data}&issuer=PedroSancao";
        $hotp = HOTP::create($base32Data);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertEquals($uri, $hotp->getUri('john.doe@example.com', 'PedroSancao'));
    }

    /** @test */
    public function it_should_throw_exception_on_invalid_base32()
    {
        $invalidBase32Data = 'PJ3HGS3XN5JEI4T8JNQW26DFJFDHQZLGCVGWUVOSG2GZ8GOCOWXIVDYQELQE2KG3';
        $this->expectException(Exception::class);
        HOTP::create($invalidBase32Data);
    }

    /** @test */
    public function it_should_throw_exception_on_invalid_uri_scheme()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $invalidScheme = 'https';
        $uri = "{$invalidScheme}://hotp/PedroSancao:john.doe%40example.com?secret={$base32Data}&issuer=PedroSancao";
        $this->expectException(Exception::class);
        HOTP::createFromURI($uri);
    }

    /** @test */
    public function it_should_throw_exception_on_invalid_uri_password_type()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $invalidType = 'https';
        $uri = "otpauth://{$invalidType}/PedroSancao:john.doe%40example.com?secret={$base32Data}&issuer=PedroSancao";
        $this->expectException(Exception::class);
        HOTP::createFromURI($uri);
    }

    /** @test */
    public function it_should_throw_exception_on_uri_without_secret()
    {
        $uri = "otpauth://hotp/PedroSancao:john.doe%40example.com?issuer=PedroSancao";
        $this->expectException(Exception::class);
        HOTP::createFromURI($uri);
    }

    /** @test */
    public function it_should_generate_correct_password()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $hotp = HOTP::create($base32Data);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertEquals('395051', $hotp->getPassword());
    }

    /** @test */
    public function it_should_generate_correct_password_with_counter()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $hotp = HOTP::create($base32Data);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertEquals('478792', $hotp->getPassword(53535760));
    }

    /** @test */
    public function it_should_verify_correct_code()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $hotp = HOTP::create($base32Data);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertTrue($hotp->verify('478792', 53535760));
    }

    /** @test */
    public function it_should_verify_incorrect_code()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $hotp = HOTP::create($base32Data);
        $this->assertInstanceOf(HOTP::class, $hotp);
        $this->assertFalse($hotp->verify('954912', 53535760));
        $this->assertFalse($hotp->verify('928895', 53535760));
    }
}
