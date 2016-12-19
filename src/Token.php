<?php

namespace Lunasci\Hmac;


class Token
{
    /**
     * The key
     *
     * @var string
     */
    protected $key;

    /**
     * The secret
     *
     * @var secret
     */
    protected $secret;

    /**
     * Create a new instance of Token
     *
     * Token constructor.
     * @param $key
     * @param $secret
     */
    public function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return secret
     */
    public function getSecret()
    {
        return $this->secret;
    }


}