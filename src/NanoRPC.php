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

        // Transport options. Nano RPC never redirects, so redirects are
        // not followed unless a caller opts in (follow_location => true);
        // even then an https -> http downgrade is refused and credentials
        // (Authorization header) are dropped when the origin changes.
        $this->options =
        [
            'timeout'         => 30,
            'headers'         => [],
            'follow_location' => false,
            'max_redirects'   => 10,
            'user_agent'      => 'NanoPHP/NanoRPC',
            // Largest response body accepted, in bytes (null = unlimited).
            // Generous for any real RPC answer, but a malicious node can't
            // exhaust memory with an endless body.
            'max_response_size' => 64 * 1024 * 1024
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

    public function setNanoApiKey(#[\SensitiveParameter] string $nano_api_key)
    {
        if (empty($nano_api_key)) {
            throw new NanoRPCException("Invalid Nano API key: empty");
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

        $endpoint = "{$this->protocol}://{$this->hostname}:{$this->port}/{$this->url}";

        [$this->responseRaw, $this->status] = $this->httpPost($endpoint, $request);

        if ($this->responseRaw === false) {
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


    // *
    // *  HTTP transport
    // *

    /**
     * POST $body to $endpoint, following redirects only when the caller
     * opted in. Returns [response body or false, HTTP status]; on failure
     * error is set.
     *
     * @return array{0: string|false, 1: int}
     */
    private function httpPost(string $endpoint, string $body): array
    {
        $method    = 'POST';
        $headers   = $this->options['headers'];
        $redirects = 0;

        while (true) {
            [$raw, $response_headers] = $this->httpRequest($endpoint, $method, $body, $headers);

            // HTTP status (and Location) of this hop
            $status   = 0;
            $location = null;
            foreach ($response_headers as $header) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $match)) {
                    $status   = (int) $match[1];
                    $location = null;
                } elseif (stripos($header, 'Location:') === 0) {
                    $location = trim(substr($header, 9));
                }
            }

            if ($raw === false) {
                $last_error  = error_get_last();
                $this->error = $last_error['message'] ?? "Unable to connect to $endpoint";

                return [false, $status];
            }

            $max_size = $this->options['max_response_size'];
            if ($max_size !== null && strlen($raw) > (int) $max_size) {
                $this->error = "Response exceeds max_response_size ($max_size bytes)";

                return [false, $status];
            }

            if (!$this->options['follow_location'] ||
                !in_array($status, [301, 302, 303, 307, 308], true) ||
                $location === null || $location === ''
            ) {
                return [$raw, $status];
            }

            if (++$redirects > (int) $this->options['max_redirects']) {
                $this->error = 'Too many redirects';

                return [false, $status];
            }

            $next = self::resolveRedirect($endpoint, $location);
            if ($next === null) {
                $this->error = 'Invalid redirect location';

                return [false, $status];
            }
            if (!self::redirectAllowed($endpoint, $next)) {
                $this->error = 'Refusing redirect from https to a non-https location';

                return [false, $status];
            }

            // Never forward credentials to another origin
            if (self::origin($next) !== self::origin($endpoint)) {
                $headers = array_values(array_filter($headers, function ($header) {
                    return stripos(ltrim((string) $header), 'Authorization:') !== 0;
                }));
            }

            // Like PHP's own http wrapper: 307/308 repeat the POST,
            // 301/302/303 continue with a body-less GET
            if ($status !== 307 && $status !== 308) {
                $method = 'GET';
                $body   = '';
            }

            $endpoint = $next;
        }
    }

    /**
     * One HTTP request without automatic redirects.
     *
     * @return array{0: string|false, 1: array} [body or false, response headers]
     */
    private function httpRequest(string $endpoint, string $method, string $body, array $extra_headers): array
    {
        $headers = '';
        if ($method === 'POST') {
            $headers .= "Content-Type: application/json\r\n"
                      . "Content-Length: " . strlen($body) . "\r\n";
        }

        foreach ($extra_headers as $header) {
            $headers .= rtrim($header, "\r\n") . "\r\n";
        }

        $http = [
            'method'          => $method,
            'header'          => $headers,
            'timeout'         => $this->options['timeout'],
            'user_agent'      => $this->options['user_agent'],
            'follow_location' => 0,
            'ignore_errors'   => true
        ];
        if ($method === 'POST') {
            $http['content'] = $body;
        }

        $context = stream_context_create(['http' => $http]);

        // Read at most one byte past the cap, so an oversized body is
        // detected without being buffered in full
        $max_size = $this->options['max_response_size'];
        $max_read = $max_size === null ? null : (int) $max_size + 1;

        $raw = @file_get_contents($endpoint, false, $context, 0, $max_read);

        if (function_exists('http_get_last_response_headers')) {
            return [$raw, http_get_last_response_headers() ?? []];
        }

        return [$raw, $http_response_header ?? []];
    }

    /** scheme://host:port of a URL (lowercased), or '' if unparsable */
    private static function origin(string $url): string
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return '';
        }

        $scheme = strtolower($parts['scheme']);
        $port   = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        return $scheme . '://' . strtolower($parts['host']) . ':' . $port;
    }

    /** Absolute http(s) URL for a Location value relative to $base, or null */
    private static function resolveRedirect(string $base, string $location): ?string
    {
        if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $location)) {
            $url = $location;
        } else {
            $parts = parse_url($base);
            if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
                return null;
            }

            $authority = $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');

            if (strpos($location, '//') === 0) {
                $url = $parts['scheme'] . ':' . $location;
            } elseif (strpos($location, '/') === 0) {
                $url = $parts['scheme'] . '://' . $authority . $location;
            } else {
                $dir = preg_replace('#/[^/]*$#', '/', $parts['path'] ?? '/');
                $url = $parts['scheme'] . '://' . $authority . $dir . $location;
            }
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if (($scheme !== 'http' && $scheme !== 'https') || parse_url($url, PHP_URL_HOST) === null) {
            return null;
        }

        return $url;
    }

    /** Redirects may never downgrade from https to http */
    private static function redirectAllowed(string $from, string $to): bool
    {
        $from_scheme = strtolower((string) parse_url($from, PHP_URL_SCHEME));
        $to_scheme   = strtolower((string) parse_url($to, PHP_URL_SCHEME));

        return !($from_scheme === 'https' && $to_scheme !== 'https');
    }
}
