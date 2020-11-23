<?php

namespace PedroSancao\OTP;

use PedroSancao\Base32;
use PedroSancao\Random;

class HOTP
{
    const ALGORITHM_SHA1 = 'sha1';
    const ALGORITHM_SHA256 = 'sha256';
    const ALGORITHM_SHA512 = 'sha512';

    /**
     * Implementation type
     *
     * @var string
     */
    protected static $type = 'hotp';

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
     * Algorithm used on hash function
     *
     * @var string
     */
    protected $algorithm = self::ALGORITHM_SHA1;

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
     * Set hashing algorithm to SHA-1
     *
     * @return $this
     */
    public function useSha1()
    {
        $this->algorithm = self::ALGORITHM_SHA1;
        return $this;
    }

    /**
     * Set hashing algorithm to SHA-256
     *
     * @return $this
     */
    public function useSha256()
    {
        $this->algorithm = self::ALGORITHM_SHA256;
        return $this;
    }

    /**
     * Set hashing algorithm to SHA-512
     *
     * @return $this
     */
    public function useSha512()
    {
        $this->algorithm = self::ALGORITHM_SHA512;
        return $this;
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
                throw new Exception('Invalid base 32 secret');
            }
        }
        return static::createRaw($secret, $size);
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
     * @param string $uri
     * @return static
     *
     * @throws Exception
     */
    public static function createFromURI($uri, $size = 6)
    {
        $fragments = parse_url($uri);

        if ($fragments === false || !key_exists('scheme', $fragments) || $fragments['scheme'] !== 'otpauth' || !key_exists('query', $fragments)) {
            throw new Exception('Invalid one time password URI');
        }
        if (!key_exists('host', $fragments) || $fragments['host'] !== static::$type) {
            throw new Exception('Invalid one time password type');
        }
        $query = [];
        parse_str($fragments['query'], $query);
        if (!key_exists('secret', $query)) {
            throw new Exception('URI contains no secret');
        }

        return static::create($query['secret'], $size);
    }

    /**
     * Generates a HMAC based password
     *
     * @param int $counter
     * @return string
     */
    public function generatePassword($counter = null)
    {
        // pack as 64 bits int
        $counterBytes = pack('N*', 0, $counter);
        // calculate HMAC hash
        $hash = hash_hmac($this->algorithm, $counterBytes, $this->secret, true);
        // get 4 bit int
        $offset = ord($hash[strlen($hash) - 1]) & 0xF;
        // get 31 bits int from offset
        $code = unpack('Nint', substr($hash, $offset, 4))['int'] & 0x7FFFFFFF;
        // format size
        return str_pad($code % pow(10, $this->size), $this->size, 0, STR_PAD_LEFT);
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
            if ($this->generatePassword($counter) === $password) {
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
        return trim(chunk_split($this->getSecret(), 4, ' '));
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
        $params = array('secret' => $this->getSecret());
        $encodedLabel = rawurlencode($label);
        if (!is_null($issuer)) {
            $encodedLabel = rawurlencode($issuer) . ':' . $encodedLabel;
            $params['issuer'] = $issuer;
        }
        return sprintf('otpauth://%s/%s?%s', static::$type, $encodedLabel, http_build_query($params));
    }

}
