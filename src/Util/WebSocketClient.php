<?php

namespace GigaionLLC\NanoPHP\Util;

use \Exception;

class WebSocketClientException extends Exception{}

/**
 * Minimal RFC 6455 WebSocket client over native PHP streams.
 *
 * Bundled so that NanoWS works without any third-party packages.
 * Supports ws:// out of the box; wss:// requires the openssl extension.
 * Text/binary messages, fragmentation (in and out), ping/pong and
 * close handshakes are handled. Compression extensions are not.
 */
class WebSocketClient
{
    private const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

    private $socket;
    private float $timeout;
    private int $fragmentSize;
    private int $maxMessageSize;
    private bool $closed = false;

    /**
     * @param string $url     ws://host:port/path or wss://host:port/path
     * @param array  $options timeout (seconds, default 60), fragment_size
     *                        (outgoing, default 4096), max_message_size
     *                        (incoming cap in bytes, default 16 MiB),
     *                        headers (list of extra handshake header lines),
     *                        context (stream context options array, e.g. ssl)
     */
    public function __construct(string $url, array $options = [])
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['host']) || !isset($parts['scheme'])) {
            throw new WebSocketClientException("Invalid WebSocket URL: $url");
        }
        if ($parts['scheme'] != 'ws' && $parts['scheme'] != 'wss') {
            throw new WebSocketClientException("Invalid WebSocket scheme: {$parts['scheme']}");
        }
        if ($parts['scheme'] == 'wss' && !extension_loaded('openssl')) {
            throw new WebSocketClientException('wss requires the openssl extension, which is not loaded');
        }

        $secure = $parts['scheme'] == 'wss';
        $host   = $parts['host'];
        $port   = $parts['port'] ?? ($secure ? 443 : 80);
        $path   = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');

        $this->timeout        = (float) ($options['timeout'] ?? 60);
        $this->fragmentSize   = (int) ($options['fragment_size'] ?? 4096);
        $this->maxMessageSize = (int) ($options['max_message_size'] ?? 16 * 1024 * 1024);

        $context = stream_context_create($options['context'] ?? []);
        $remote  = ($secure ? 'ssl://' : 'tcp://') . $host . ':' . $port;

        $this->socket = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            $this->timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($this->socket === false) {
            throw new WebSocketClientException("Could not connect to $remote: $errstr ($errno)");
        }

        stream_set_timeout($this->socket, (int) $this->timeout, (int) (($this->timeout - (int) $this->timeout) * 1e6));

        $this->handshake($host, $port, $path, $options['headers'] ?? []);
    }

    private function handshake(string $host, int $port, string $path, array $extra_headers): void
    {
        $key = base64_encode(random_bytes(16));

        $request = "GET $path HTTP/1.1\r\n"
                 . "Host: $host:$port\r\n"
                 . "Upgrade: websocket\r\n"
                 . "Connection: Upgrade\r\n"
                 . "Sec-WebSocket-Key: $key\r\n"
                 . "Sec-WebSocket-Version: 13\r\n"
                 . "User-Agent: NanoPHP/WebSocketClient\r\n";

        foreach ($extra_headers as $header) {
            $request .= rtrim($header, "\r\n") . "\r\n";
        }

        $this->write($request . "\r\n");

        // Read response headers until the blank line
        $response = '';
        while (strpos($response, "\r\n\r\n") === false) {
            $line = fgets($this->socket, 8192);
            if ($line === false) {
                throw new WebSocketClientException('Connection closed during WebSocket handshake');
            }
            $response .= $line;
        }

        if (!preg_match('#^HTTP/\S+\s+101#', $response)) {
            throw new WebSocketClientException('WebSocket handshake rejected: ' . strtok($response, "\r\n"));
        }

        $expected = base64_encode(sha1($key . self::GUID, true));
        if (!preg_match('/^Sec-WebSocket-Accept:\s*(\S+)/mi', $response, $match) ||
            $match[1] !== $expected
        ) {
            throw new WebSocketClientException('Invalid Sec-WebSocket-Accept in handshake response');
        }
    }


    // *
    // *  Public API
    // *

    public function send(string $payload, string $type = 'text'): void
    {
        $opcode = $type == 'binary' ? 0x2 : 0x1;

        if ($this->closed) {
            throw new WebSocketClientException('WebSocket connection is closed');
        }

        // Fragment outgoing messages: first frame carries the opcode,
        // continuations carry 0x0, the last frame sets FIN
        $chunks = str_split($payload, max(1, $this->fragmentSize)) ?: [''];
        $last   = count($chunks) - 1;

        foreach ($chunks as $i => $chunk) {
            $this->writeFrame($i == 0 ? $opcode : 0x0, $chunk, $i == $last);
        }
    }

    /**
     * Receive the next complete text/binary message.
     * Returns null on read timeout; throws once the connection closes.
     */
    public function receive(): ?string
    {
        if ($this->closed) {
            throw new WebSocketClientException('WebSocket connection is closed');
        }

        $message = '';

        while (true) {
            $frame = $this->readFrame();
            if ($frame === null) {
                return null; // timeout
            }

            [$opcode, $payload, $fin] = $frame;

            switch ($opcode) {
                case 0x1: // text
                case 0x2: // binary
                case 0x0: // continuation
                    $message .= $payload;
                    if (strlen($message) > $this->maxMessageSize) {
                        $this->close(1009); // message too big
                        throw new WebSocketClientException(
                            "Incoming message exceeds max_message_size ({$this->maxMessageSize} bytes)"
                        );
                    }
                    if ($fin) {
                        return $message;
                    }
                    break;

                case 0x9: // ping -> pong with same payload
                    $this->writeFrame(0xA, $payload, true);
                    break;

                case 0xA: // pong, ignore
                    break;

                case 0x8: // close -> echo and shut down
                    if (!$this->closed) {
                        $this->closed = true;
                        @$this->writeFrame(0x8, $payload, true);
                        fclose($this->socket);
                    }
                    throw new WebSocketClientException('WebSocket connection closed by peer');

                default:
                    throw new WebSocketClientException("Unsupported WebSocket opcode: $opcode");
            }
        }
    }

    public function close(int $status = 1000): void
    {
        if ($this->closed || !is_resource($this->socket)) {
            $this->closed = true;
            return;
        }

        $this->closed = true;
        @$this->writeFrame(0x8, pack('n', $status), true);
        @fclose($this->socket);
    }

    public function isConnected(): bool
    {
        return !$this->closed && is_resource($this->socket);
    }

    public function __destruct()
    {
        $this->close();
    }


    // *
    // *  Frame I/O
    // *

    private function writeFrame(int $opcode, string $payload, bool $fin): void
    {
        $frame = chr(($fin ? 0x80 : 0x00) | $opcode);

        // Client frames must be masked
        $length = strlen($payload);
        if ($length < 126) {
            $frame .= chr(0x80 | $length);
        } elseif ($length < 65536) {
            $frame .= chr(0x80 | 126) . pack('n', $length);
        } else {
            $frame .= chr(0x80 | 127) . pack('J', $length);
        }

        $mask  = random_bytes(4);
        $frame .= $mask;

        for ($i = 0; $i < $length; $i++) {
            $frame .= $payload[$i] ^ $mask[$i % 4];
        }

        $this->write($frame);
    }

    /** @return ?array [opcode, payload, fin], or null on read timeout */
    private function readFrame(): ?array
    {
        $header = $this->read(2);
        if ($header === null) {
            return null;
        }

        $byte1 = ord($header[0]);
        $byte2 = ord($header[1]);

        $fin    = (bool) ($byte1 & 0x80);
        $opcode = $byte1 & 0x0f;
        $masked = (bool) ($byte2 & 0x80);
        $length = $byte2 & 0x7f;

        if ($length == 126) {
            $length = unpack('n', $this->readStrict(2))[1];
        } elseif ($length == 127) {
            $length = unpack('J', $this->readStrict(8))[1];
        }

        // Refuse to allocate for an oversized (or, on the 64-bit wire,
        // negative-when-wrapped) frame a malicious peer might claim
        if ($length < 0 || $length > $this->maxMessageSize) {
            $this->close(1009); // message too big
            throw new WebSocketClientException(
                "Incoming frame length $length exceeds max_message_size ({$this->maxMessageSize} bytes)"
            );
        }

        $mask = $masked ? $this->readStrict(4) : '';

        $payload = $length > 0 ? $this->readStrict($length) : '';

        if ($masked) {
            for ($i = 0; $i < $length; $i++) {
                $payload[$i] = $payload[$i] ^ $mask[$i % 4];
            }
        }

        return [$opcode, $payload, $fin];
    }

    private function write(string $data): void
    {
        $written = @fwrite($this->socket, $data);
        if ($written !== strlen($data)) {
            $this->closed = true;
            throw new WebSocketClientException('Could not write to WebSocket');
        }
    }

    /** Read exactly $length bytes; null if the read timed out before the first byte */
    private function read(int $length): ?string
    {
        $data = '';
        while (strlen($data) < $length) {
            $chunk = @fread($this->socket, $length - strlen($data));

            if ($chunk === '' || $chunk === false) {
                $meta = stream_get_meta_data($this->socket);
                if (!empty($meta['timed_out'])) {
                    if ($data === '') {
                        return null;
                    }
                    // Timed out mid-frame: keep waiting for the rest
                    continue;
                }
                $this->closed = true;
                throw new WebSocketClientException('WebSocket connection lost');
            }

            $data .= $chunk;
        }

        return $data;
    }

    private function readStrict(int $length): string
    {
        while (true) {
            $data = $this->read($length);
            if ($data !== null) {
                return $data;
            }
            // Timeout between frame header and body: keep waiting
        }
    }
}
