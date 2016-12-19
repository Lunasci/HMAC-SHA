<?php

namespace Lunasci\Hmac;

use Lunasci\Hmac\Request;
use Lunasci\Hmac\Token;

class Hmac
{
    /**
     * Token
     *
     * @param $key
     * @param $secret
     * @return Token
     */
    public function token($key, $secret)
    {
        return new Token($key, $secret);
    }

    /**
     * Request
     *
     * @param $method
     * @param $path
     * @param array $params
     * @return Request
     */
    public  function request($method, $path, array $params)
    {
        return new Request($method, $path, $params);
    }
}