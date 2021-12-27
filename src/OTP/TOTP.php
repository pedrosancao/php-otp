<?php

namespace PedroSancao\OTP;

class TOTP extends HOTP
{

    /**
     * Implementation type
     *
     * @var string
     */
    protected static $type = 'totp';

    /**
     * Max verication window size
     *
     * @var int
     */
    protected $maxWindowSize = 3;

    /**
     * Time step size, in seconds
     *
     * @var int
     */
    private $timeStep = 30;

    /**
     * Gets default counter value
     *
     * @return int
     */
    protected function getDefaultCounter()
    {
        return time();
    }

    /**
     * Gets current Time Step value
     *
     * @return int
     */
    public function getTimeStep()
    {
        return $this->timeStep;
    }

    /**
     * Sets Time Step value
     *
     * @param int $step
     * @return int
     * @throws Exception
     */
    public function setTimeStep($step)
    {
        if (! is_int($step) || ! $step > 0) {
            throw new Exception('Invalid time step');
        }

        return $this->timeStep = $step;
    }

    /**
     * Apply on counter before generation password
     *
     * @param int $counter
     */
    protected function counterHook(&$counter)
    {
        $counter = floor($counter / $this->timeStep);
    }
    
    /**
     * Gets password
     *
     * @param int $timestamp
     * @return string
     */
    public function getPassword($timestamp = null)
    {
        return parent::getPassword($timestamp);
    }

    /**
     *
     * @param string $password
     * @param int $timestamp
     * @param int $window how many passwords to verify against
     */
    public function verify($password, $timestamp = null, $window = 2)
    {
        return parent::verify($password, $timestamp, $window);
    }

}
