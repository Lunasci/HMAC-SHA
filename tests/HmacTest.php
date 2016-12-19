<?php

use Lunasci\Hmac\Hmac;

class HmacTest extends PHPUnit_Framework_TestCase
{

    public function makeRequest()
    {
        // Create new Hmac instance
        $hmac = new Hmac();

        // Create params
        $params = ['name' => 'Luis Perez', 'email' => 'luis.perez@lunasci.com'];

        // Create Token
        $token = $hmac->token('my_key', 'my_secret');

        // Create Request
        $request = $hmac->request('POST', '/api/thing', $params);

        // Sign the request
        $auth_params = $request->sign($token);

        // Create query params
        return array_merge($params, $auth_params);
    }

    /**
     * @expectedException Exception
     */
    public function testExceptionWhenRequestParamsNotArray()
    {
        // Create new Hmac instance
        $hmac = new Hmac();
        $request = $hmac->request('POST', '/api/thing', 'not an array');
    }

    public function testAuthenticateRequestSuccess()
    {
        // Create new Hmac instance
        $hmac = new Hmac();

        // Create Token
        $token = $hmac->token('my_key', 'my_secret');

        // Create Request
        $request = $hmac->request('POST', '/api/thing', $this->makeRequest());

        // Assert authenticated request
        $this->assertTrue($request->authenticate($token));
    }

    /**
     * @expectedException Lunasci\Hmac\Exception\AuthenticationException
     * @expectedExceptionMessage The auth_key is incorrect
     */
    public function testAuthenticationRequestIncorrectKey()
    {
        // Create new Hmac instance
        $hmac = new Hmac();

        // Create Token
        $token = $hmac->token('not_my_key', 'my_secret');

        // Create Request
        $request = $hmac->request('POST', '/api/thing', $this->makeRequest());

        // Attempt to authenticate
        $request->authenticate($token);
    }

    /**
     * @expectedException Lunasci\Hmac\Exception\AuthenticationException
     * @expectedExceptionMessage The auth_version is incorrect
     */
    public function testAuthenticationRequestIncorrectVersion()
    {
        // Create new Hmac instance
        $hmac = new Hmac();

        // Create Token
        $token = $hmac->token('my_key', 'not_my_secret');

        // Change params
        $params = $this->makeRequest();
        $params['auth_version'] = '1.1';

        // Create Request
        $request = $hmac->request('POST', '/api/thing', $params);

        // Attempt to authenticate
        $request->authenticate($token);
    }

    /**
     * @expectedException Lunasci\Hmac\Exception\AuthenticationException
     * @expectedExceptionMessage The auth_timestamp is invalid
     */
    public function testAuthenticationRequestIncorrectTimestamp()
    {
        // Create new Hmac instance
        $hmac = new Hmac();

        // Create Token
        $token = $hmac->token('my_key', 'my_secret');

        // Change params
        $params = $this->makeRequest();
        $params['auth_timestamp'] = time() + (7 * 24 * 60 * 60);

        // Create Request
        $request = $hmac->request('POST', '/api/thing', $params);

        // Attempt to authenticate
        $request->authenticate($token);
    }

    /**
     * @expectedException Lunasci\Hmac\Exception\AuthenticationException
     * @expectedExceptionMessage The auth_signature is incorrect
     */
    public function testAuthenticationRequestIncorrectSignature()
    {
        // Create new Hmac instance
        $hmac = new Hmac();

        // Create Token
        $token = $hmac->token('my_key', 'my_secret');

        // Change params
        $params = $this->makeRequest();
        $params['auth_signature'] = 'secure signature. many character. so wow';

        // Create Request
        $request = $hmac->request('POST', '/api/thing', $params);

        // Attempt to authenticate
        $request->authenticate($token);
    }

}