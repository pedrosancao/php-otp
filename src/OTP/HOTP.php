<?php

namespace PedroSancao\OTP;

use PedroSancao\Base32;
use PedroSancao\Random;
use Exception;

class HOTP
{

    /**
     * Implementation type
     *
     * @var string
     */
    protected $type = 'hotp';

    /**
     * Max verication window size
     *
     * @var int
     */
    protected $maxWindowSize = 1;

    /**
     * Bytes secret, as string
     *
     * @var string
     */
    protected $secret;

    /**
     * Size of generated password
     *
     * @var int
     */
    protected $size;

    /**
     * @param string $secret
     * @param int $size
     */
    protected function __construct($secret, $size)
    {
        $this->secret = $secret;
        $this->size = $size;
    }

    /**
     * Gets default counter value
     *
     * @return int
     */
    protected function getDefaultCounter()
    {
        return 1;
    }

    /**
     * Apply on counter before generation password
     *
     * @param int $counter
     */
    protected function counterHook(&$counter)
    {
    }

    /**
     * Creates from base 32 encoded secret
     *
     * @param string $secret
     * @param int $size
     * @return HOTP
     * @throws Exception
     */
    public static function create($secret = null, $size = 6)
    {
        if (!is_null($secret)) {
            $secret = Base32::decode($secret);
            if ($secret === false) {
                throw new Exception('invalid base 32 secret');
            }
        }
        return self::createRaw($secret, $size);
    }

    /**
     * Creates from bytes secret string
     *
     * @param string $secret
     * @param int $size
     * @return HOTP
     */
    public static function createRaw($secret = null, $size = 6)
    {
        if (is_null($secret)) {
            $secret = Random::raw(15);
        }
        return new static($secret, $size);
    }

    /**
     * Create the object from URI
     *
     * @todo implment
     * @param string $uri
     */
    public static function createFromURI($uri)
    {
        return false;
    }

    /**
     * Generates a HMAC based password
     * 
     * @param int $counter
     * @return string
     */
    public function generatePassword($counter = null)
    {
        $couterBytesArr = array(); // encode every byte in counter as ASCII
        while ($counter != 0) {
            $couterBytesArr[] = chr($counter & 0xFF);
            $counter >>= 8;
        }
        $couterBytes = str_pad(join(array_reverse($couterBytesArr)), 8, chr(0), STR_PAD_LEFT);
        $hash = hash_hmac('sha1', $couterBytes, $this->secret);
        $offset = hexdec(substr($hash, 38)) & 0xF; // 2 last hexadecimal chars (last byte)
        $hashParts = str_split(substr($hash, $offset * 2, 8), 2); // 4 bytes as array
        $code =
            (hexdec($hashParts[0]) & 0x7F) << 24 |
            hexdec($hashParts[1]) << 16 |
            hexdec($hashParts[2]) << 8 |
            hexdec($hashParts[3]);
        return $code % pow(10, $this->size);
    }

    /**
     * Gets password
     *
     * @param int $counter
     * @return string
     */
    public function getPassword($counter = null)
    {
        if (is_null($counter)) {
            $counter = $this->getDefaultCounter();
        }
        $this->counterHook($counter);
        return $this->generatePassword($counter);
    }

    /**
     *
     * @param string $password
     * @param int $counter
     * @param int $window how many passwords to verify against
     */
    public function verify($password, $counter = null, $window = 1)
    {
        if (is_null($counter)) {
            $counter = $this->getDefaultCounter();
        }
        $this->counterHook($counter);
        if ($window > $this->maxWindowSize || $window < 1) {
            $window = max($this->maxWindowSize, min(1, $window));
        }
        $counter += 1 - ceil($window / 2);
        for ($i = 0; $i < $window; $i++, $counter++) {
            if ($this->generatePassword($counter) == $password) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets the secret encoded in base 32
     *
     * @return string
     */
    public function getSecret()
    {
        return Base32::encode($this->secret, false);
    }

    /**
     * Gets the secret encoded in base 32
     *
     * @return string
     */
    public function getRawSecret()
    {
        return $this->secret;
    }

    /**
     * Gets the secret encoded in base 32 with added spaces for readability
     *
     * @return string
     */
    public function getSecretReadable()
    {
        return chunk_split($this->getSecret(), 4, ' ');
    }

    /**
     * Gets the URI for configuration
     *
     * @param string $label
     * @param string $issuer
     * @return string
     */
    public function getUri($label, $issuer = null)
    {
        $params = array('secret' => $this->secret);
        if (!is_null($issuer)) {
            $label = $issuer . ':' . $label;
            $params['issuer'] = $issuer;
        }
        return sprintf('otpauth://%s/%s?%s', $this->type, rawurlencode($label), http_build_query($params));
    }

}
