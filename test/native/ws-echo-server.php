<?php

// Minimal RFC 6455 echo server for testing the bundled WebSocket client.
// Handles one client at a time, in an accept loop (port probes and
// reconnects are fine). Sends an unsolicited ping after the handshake,
// then echoes every text message back. Test-only; not for production.
//
//   php test/native/ws-echo-server.php 17078

class ClientGone extends Exception{}

$port   = (int) ($argv[1] ?? 17078);
$server = stream_socket_server("tcp://127.0.0.1:$port", $errno, $errstr);

if ($server === false) {
    fwrite(STDERR, "listen failed: $errstr\n");
    exit(1);
}

function readBytes($socket, int $length): string
{
    $data = '';
    while (strlen($data) < $length) {
        $chunk = fread($socket, $length - strlen($data));
        if ($chunk === '' || $chunk === false) {
            throw new ClientGone('client disconnected');
        }
        $data .= $chunk;
    }
    return $data;
}

function sendFrame($socket, int $opcode, string $payload): void
{
    $frame = chr(0x80 | $opcode);
    $length = strlen($payload);
    if ($length < 126) {
        $frame .= chr($length);
    } elseif ($length < 65536) {
        $frame .= chr(126) . pack('n', $length);
    } else {
        $frame .= chr(127) . pack('J', $length);
    }
    fwrite($socket, $frame . $payload);
}

function serveClient($client): void
{
    // * Handshake

    $request = '';
    while (strpos($request, "\r\n\r\n") === false) {
        $line = fgets($client, 8192);
        if ($line === false) {
            throw new ClientGone('disconnected during handshake'); // e.g. a port probe
        }
        $request .= $line;
    }

    if (!preg_match('/^Sec-WebSocket-Key:\s*(\S+)/mi', $request, $match)) {
        fwrite($client, "HTTP/1.1 400 Bad Request\r\n\r\n");
        throw new ClientGone('not a websocket handshake');
    }

    $accept = base64_encode(sha1($match[1] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));

    fwrite($client,
        "HTTP/1.1 101 Switching Protocols\r\n" .
        "Upgrade: websocket\r\n" .
        "Connection: Upgrade\r\n" .
        "Sec-WebSocket-Accept: $accept\r\n\r\n"
    );

    // Unsolicited ping the client must answer
    sendFrame($client, 0x9, 'are-you-there');

    // * Echo loop (reassembles fragmented client messages)

    $message = '';
    while (true) {
        $header = readBytes($client, 2);
        $byte1  = ord($header[0]);
        $byte2  = ord($header[1]);

        $fin    = (bool) ($byte1 & 0x80);
        $opcode = $byte1 & 0x0f;
        $length = $byte2 & 0x7f;

        if ($length == 126) {
            $length = unpack('n', readBytes($client, 2))[1];
        } elseif ($length == 127) {
            $length = unpack('J', readBytes($client, 8))[1];
        }

        $mask    = ($byte2 & 0x80) ? readBytes($client, 4) : '';
        $payload = $length > 0 ? readBytes($client, $length) : '';

        if ($mask !== '') {
            for ($i = 0; $i < $length; $i++) {
                $payload[$i] = $payload[$i] ^ $mask[$i % 4];
            }
        }

        switch ($opcode) {
            case 0x1:
            case 0x2:
            case 0x0:
                $message .= $payload;
                if ($fin) {
                    sendFrame($client, 0x1, $message);
                    $message = '';
                }
                break;

            case 0x9: // ping from client
                sendFrame($client, 0xA, $payload);
                break;

            case 0xA: // pong (answer to our ping)
                break;

            case 0x8: // close
                sendFrame($client, 0x8, $payload);
                throw new ClientGone('closed');
        }
    }
}

while (true) {
    $client = @stream_socket_accept($server, 30);
    if ($client === false) {
        exit(0); // idle, shut down
    }

    try {
        serveClient($client);
    } catch (ClientGone $e) {
        @fclose($client);
    }
}
