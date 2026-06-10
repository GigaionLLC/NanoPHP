<?php

namespace GigaionLLC\NanoPHP;

use \Exception;

class NanoRPCException extends Exception{}

class NanoRPC
{
    // * Settings

    private $protocol;
    private $hostname;
    private $port;
    private $url;
    private $options;
    private $nanoApi;
    private $nanoApiKey;
    private $id = 0;


    // * Results and debug

    public $response;
    public $responseRaw;
    public $responseType;
    public $responseTime;
    public $status;
    public $error;
    public $errorCode;


    // *
    // *  Initialization
    // *

    public function __construct(
        string $protocol = 'http',
        string $hostname = 'localhost',
        int    $port     = 7076,
        ?string $url      = null,
        ?array  $options  = null
    ) {
        // Protocol
        if ($protocol != 'http' &&
            $protocol != 'https'
        ) {
            throw new NanoRPCException("Invalid protocol: $protocol");
        }
        if ($protocol == 'https' && !extension_loaded('openssl')) {
            throw new NanoRPCException("https requires the openssl extension, which is not loaded");
        }

        // Url
        if (!empty($url)) {
            if (strpos($url, '/') === 0) {
                $url = substr($url, 1);
            }
        }

        $this->protocol = $protocol;
        $this->hostname = $hostname;
        $this->port     = $port;
        $this->url      = $url;
        $this->nanoApi  = 1;

        // Transport options
        $this->options =
        [
            'timeout'         => 30,
            'headers'         => [],
            'follow_location' => true,
            'max_redirects'   => 10,
            'user_agent'      => 'NanoPHP/NanoRPC'
        ];

        if (is_array($options)) {
            foreach ($options as $key => $value) {
                $this->options[$key] = $value;
            }
        }
    }


    // *
    // *  Set Nano API
    // *

    public function setNanoApi(int $nano_api)
    {
        if ($nano_api != 1 &&
            $nano_api != 2
        ) {
            throw new NanoRPCException("Invalid Nano API: $nano_api");
        }

        $this->nanoApi = $nano_api;
    }


    // *
    // *  Set Nano API key
    // *

    public function setNanoApiKey(string $nano_api_key)
    {
        if (empty($nano_api_key)) {
            throw new NanoRPCException("Invalid Nano API key: $nano_api_key");
        }

        $this->nanoApiKey = (string) $nano_api_key;
    }


    // *
    // *  Call
    // *

    public function __call($method, array $params)
    {
        $this->id++;
        $this->response     = null;
        $this->responseRaw  = null;
        $this->responseType = null;
        $this->responseTime = null;
        $this->status       = null;
        $this->error        = null;
        $this->errorCode    = null;

        if (!isset($params[0])) {
            $params[0] = [];
        }


        // *
        // *  Request: API switch
        // *

        // * v1

        if ($this->nanoApi == 1) {
            $request = $params[0];
            $request['action'] = $method;


        // * v2

        } elseif ($this->nanoApi == 2) {
            $request = [
                'correlation_id' => (string) $this->id,
                'message_type'   => $method,
                'message'        => $params[0]
            ];

            // Nano API key
            if ($this->nanoApiKey != null) {
                $request['credentials'] = $this->nanoApiKey;
            }
        } else {
            throw new NanoRPCException("Invalid Nano API: {$this->nanoApi}");
        }

        $request = json_encode($request);


        // * Perform the HTTP request over native streams (no curl required)

        $headers = "Content-Type: application/json\r\n"
                 . "Content-Length: " . strlen($request) . "\r\n";

        foreach ($this->options['headers'] as $header) {
            $headers .= rtrim($header, "\r\n") . "\r\n";
        }

        $context = stream_context_create([
            'http' => [
                'method'           => 'POST',
                'header'           => $headers,
                'content'          => $request,
                'timeout'          => $this->options['timeout'],
                'user_agent'       => $this->options['user_agent'],
                'follow_location'  => $this->options['follow_location'] ? 1 : 0,
                'max_redirects'    => $this->options['max_redirects'],
                'ignore_errors'    => true
            ]
        ]);

        $endpoint = "{$this->protocol}://{$this->hostname}:{$this->port}/{$this->url}";

        $this->responseRaw = @file_get_contents($endpoint, false, $context);

        // HTTP status from response headers
        $this->status = 0;
        if (function_exists('http_get_last_response_headers')) {
            $response_headers = http_get_last_response_headers() ?? [];
        } else {
            $response_headers = $http_response_header ?? [];
        }
        foreach ($response_headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $match)) {
                $this->status = (int) $match[1];
            }
        }

        if ($this->responseRaw === false) {
            $last_error  = error_get_last();
            $this->error = $last_error['message'] ?? "Unable to connect to $endpoint";

            return false;
        }

        $this->response = json_decode($this->responseRaw, true);

        if (!is_array($this->response)) {
            $this->error = 'Invalid JSON response from node';
            $this->response = null;

            return false;
        }


        // *
        // *  Response: API switch
        // *

        // * v1

        if ($this->nanoApi == 1) {
            if (isset($this->response['error'])) {
                $this->error = $this->response['error'];
                $this->response = null;
            }


        // * v2

        } elseif ($this->nanoApi == 2) {
            $this->responseType = $this->response['message_type'] ?? null;

            $this->responseTime = (int) ($this->response['time'] ?? 0);

            if (($this->response['correlation_id'] ?? null) != $this->id) {
                $this->error = 'Correlation Id doesn\'t match';
            }

            if ($this->responseType == 'Error') {
                $this->error     = $this->response['message'];
                $this->errorCode = (int) $this->response['message']['code'];
                $this->response  = null;
            } else {
                $this->response = $this->response['message'] ?? null;
            }
        }


        // * HTTP errors

        if ($this->status != 200 && $this->error === null) {
            switch ($this->status) {
                case 400:
                    $this->error = 'HTTP_BAD_REQUEST';
                    break;

                case 401:
                    $this->error = 'HTTP_UNAUTHORIZED';
                    break;

                case 403:
                    $this->error = 'HTTP_FORBIDDEN';
                    break;

                case 404:
                    $this->error = 'HTTP_NOT_FOUND';
                    break;

                default:
                    $this->error = "HTTP_{$this->status}";
            }
        }


        // * Return

        if ($this->error) {
            return false;
        } else {
            return $this->response;
        }
    }
}
