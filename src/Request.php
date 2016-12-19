<?php

namespace Lunasci\Hmac;

use Lunasci\Hmac\Exception\AuthenticationException;

class Request
{
    /**
     * The HTTP method
     *
     * @var string
     */
    protected $method;

    /**
     * The API path
     *
     * @var string
     */
    protected $path;

    /**
     * The data to send
     *
     * @var array
     */
    protected $params;

    /**
     * The version of Hmac
     *
     * @var string
     */
    protected $version = '1.0';

    /**
     * The default auth paramters
     *
     * @var array
     */
    protected $auth_params = [
        'auth_version'   => null,
        'auth_key'       => null,
        'auth_timestamp' => null,
        'auth_signature' => null
    ];


    /**
     * The query params
     *
     * @var array
     */
    protected  $query_params = [];


    /**
     * Create a new instance of Request
     *
     * Request constructor.
     * @param $method
     * @param $path
     * @param array $params
     */
    public function __construct($method, $path, array $params)
    {
        $this->method = strtoupper($method);

        $this->path = $path;

        foreach($params as $key => $value)
        {
            $key = strtolower($key);
            substr($key, 0, 5) == 'auth_' ? $this->auth_params[$key] = $value : $this->query_params[$key] = $value;
        }
    }


    /**
     * Sign the request with a token
     *
     * @param Token $token
     * @return array
     */
    public function sign(Token $token)
    {
        $this->auth_params = [
            'auth_version'      => '1.0',
            'auth_key'          => $token->getKey(),
            'auth_timestamp'    => time()
        ];

        $this->auth_params['auth_signature'] = $this->signature($token);

        return $this->auth_params;
    }

    /**
     * Get the hashed signature
     *
     * @param Token $token
     * @return string
     */
    protected function signature(Token $token)
    {
        return hash_hmac('sha256', $this->stringToSign(), $token->getSecret());
    }

    /**
     * String to Sign
     *
     * @return string
     */
    protected function stringToSign()
    {
        return (implode("\n", [$this->method, $this->path, $this->parameterString()]));
    }

    protected function parameterString()
    {
        // Create an array to build the http query
        $array = [];

        // Merge the auth and query params
        $params = array_merge($this->auth_params, $this->query_params);

        // Convert Keys to lowercase
        foreach($params as $key => $value)
        {
            // Set each param on the array
            $array[strtolower($key)] = $value;
        }

        // Remove the signature key
        unset($array['auth_signature']);

        // Encode array to the http string
        return http_build_query($array);
    }


    /**
     * Authenticate the request
     *
     * @param Token $token
     * @param int $timestampGrace
     * @return mixed
     * @throws AuthenticationException
     */
    public function authenticate(Token $token, $timestampGrace = 600)
    {
        // Check the authentication key is correct
        if($this->auth_params['auth_key'] == $token->getKey())
        {
            return $this->authenticateByToken($token, $timestampGrace);
        }

        throw new AuthenticationException('The auth_key is incorrect');
    }


    /**
     * Authenticate By Token
     *
     * @param Token $token
     * @param $timestampGrace
     * @return bool
     */
    protected function authenticateByToken(Token $token, $timestampGrace)
    {
        //Check token
        if($token->getSecret() == null)
        {
            throw new AuthenticationException('The token secret is not set');
        }

        // Validate version
        $this->validateVersion();

        // Validate timestamp
        $this->validateTimestamp($timestampGrace);

        // Validate signature
        $this->validateSignature($token);

        return true;
    }

    /**
     * Validate Version
     *
     * @return bool
     * @throws AuthenticationException
     */
    protected function validateVersion()
    {
        if($this->auth_params['auth_version'] !== $this->version)
        {
            throw new AuthenticationException('The auth_version is incorrect');
        }

        return true;
    }

    /**
     * Validate Timestamp
     *
     * @param $timestampGrace
     * @return bool
     * @throws AuthenticationException
     */
    protected function validateTimestamp($timestampGrace)
    {
        if($timestampGrace == 0)
        {
            return true;
        }

        $difference = $this->auth_params['auth_timestamp'] - time();

        if($difference >= $timestampGrace)
        {
            throw new AuthenticationException('The auth_timestamp is invalid');
        }

        return true;
    }

    /**
     * Validate Signature
     *
     * @param Token $token
     * @return bool
     * @throws AuthenticationException
     */
    protected function validateSignature(Token $token)
    {
        if($this->auth_params['auth_signature'] !== $this->signature($token))
        {
            throw new AuthenticationException('The auth_signature is incorrect');
        }

        return true;
    }

}