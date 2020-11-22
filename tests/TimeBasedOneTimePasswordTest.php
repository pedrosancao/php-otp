<?php

namespace PedroSancao\OTP;

function time() {
    return (new \DateTime('2020-11-22 19:20:00'))->getTimestamp();
}

namespace Tests;

use DateTime;
use PedroSancao\OTP\TOTP;
use PHPUnit\Framework\TestCase;

final class TimeBasedOneTimePasswordTest extends TestCase
{
    /** @test */
    public function it_should_create_a_instance()
    {
        $totp = TOTP::create();
        $this->assertInstanceOf(TOTP::class, $totp);
    }

    /** @test */
    public function it_should_create_a_instance_from_uri()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $uri = "otpauth://totp/PedroSancao:john.doe%40example.com?secret={$base32Data}&issuer=PedroSancao";
        $totp = TOTP::createFromURI($uri);
        $this->assertInstanceOf(TOTP::class, $totp);
        $this->assertEquals($base32Data, $totp->getSecret());
    }

    /** @test */
    public function it_should_export_uri()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $uri = "otpauth://totp/PedroSancao:john.doe%40example.com?secret={$base32Data}&issuer=PedroSancao";
        $totp = TOTP::create($base32Data);
        $this->assertInstanceOf(TOTP::class, $totp);
        $this->assertEquals($uri, $totp->getUri('john.doe@example.com', 'PedroSancao'));
    }

    /** @test */
    public function it_should_generate_correct_password()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $totp = TOTP::create($base32Data);
        $this->assertInstanceOf(TOTP::class, $totp);
        $timestamp = (new DateTime('2020-11-22 19:20:00'))->getTimestamp();
        $this->assertEquals('478792', $totp->getPassword($timestamp));
    }

    /** @test */
    public function it_should_verify_correct_code()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $totp = TOTP::create($base32Data);
        $this->assertInstanceOf(TOTP::class, $totp);
        $this->assertTrue($totp->verify('478792'));
    }

    /** @test */
    public function it_should_verify_correct_code_within_even_window()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $totp = TOTP::create($base32Data);
        $this->assertInstanceOf(TOTP::class, $totp);
        $this->assertTrue($totp->verify('928895', null, 2));
    }

    /** @test */
    public function it_should_verify_correct_code_within_odd_window()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $totp = TOTP::create($base32Data);
        $this->assertInstanceOf(TOTP::class, $totp);
        $this->assertTrue($totp->verify('954912', null, 3));
        $this->assertTrue($totp->verify('928895', null, 3));
    }

    /** @test */
    public function it_should_limit_window_to_max()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $totp = TOTP::create($base32Data);
        $this->assertInstanceOf(TOTP::class, $totp);
        $maxWindowSize = new \ReflectionProperty(TOTP::class, 'maxWindowSize');
        $maxWindowSize->setAccessible(true);
        $maxWindowSize->setValue($totp, 1);
        $this->assertFalse($totp->verify('954912', null, 3));
        $this->assertFalse($totp->verify('928895', null, 3));
    }

    /** @test */
    public function it_should_()
    {
        $base32Data = 'PJ3HGS3XN5JEI4TBJNQW26DFJFDHQZLGCVGWUVOSG2GZBGOCOWXIVDYQELQE2KG3';
        $totp = TOTP::create($base32Data);
        $this->assertInstanceOf(TOTP::class, $totp);
    }
}

