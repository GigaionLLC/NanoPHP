<?php

/**
 * Tests for the bundled RFC 6455 WebSocket client and the NanoWS wrapper,
 * against the pure-PHP echo server in ws-echo-server.php.
 *
 *   php test/native/websocket.php
 */

require __DIR__ . '/../autoload.php';

use GigaionLLC\NanoPHP\NanoWS;
use GigaionLLC\NanoPHP\Util\WebSocketClient;

$failures = 0;

function check(string $name, $actual, $expected = true): void
{
    global $failures;

    if ($actual === $expected) {
        echo "PASS  $name\n";
    } else {
        $failures++;
        echo "FAIL  $name\n";
        echo "      expected: " . var_export($expected, true) . "\n";
        echo "      actual:   " . var_export($actual, true) . "\n";
    }
}

$running_server = null;

function spawnEchoServer(int $port)
{
    global $running_server;

    $server = proc_open(
        [PHP_BINARY, __DIR__ . '/ws-echo-server.php', (string) $port],
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    $running_server = $server;

    for ($i = 0; $i < 50; $i++) {
        if (!proc_get_status($server)['running']) {
            fwrite(STDERR, "Echo server exited early: " . stream_get_contents($pipes[2]) . "\n");
            exit(1);
        }

        $socket = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 0.2);
        if ($socket) {
            fclose($socket);
            return $server;
        }
        usleep(100000);
    }

    fwrite(STDERR, "Echo server did not come up\n");
    exit(1);
}

function stopEchoServer($server): void
{
    proc_terminate($server);

    // Wait for the process to actually release its socket; an immediate
    // re-spawn on the same port would otherwise race the dying listener
    for ($i = 0; $i < 50; $i++) {
        if (!proc_get_status($server)['running']) {
            return;
        }
        usleep(100000);
    }
}

register_shutdown_function(function () {
    global $running_server;
    if (is_resource($running_server)) {
        proc_terminate($running_server);
    }
});


// *
// *  Raw client: handshake, echo, fragmentation, ping handling
// *

$port   = 17078;
$server = spawnEchoServer($port);

$ws = new WebSocketClient("ws://127.0.0.1:$port/", ['timeout' => 5, 'fragment_size' => 1024]);

$ws->send('hello nano');
check('small message echoes', $ws->receive(), 'hello nano');

// Forces outgoing fragmentation (fragment_size 1024) and a 16-bit length
$large = str_repeat('A1b2', 8192); // 32 KiB
$ws->send($large);
check('32 KiB fragmented message echoes intact', $ws->receive() === $large);

// The server pinged us right after the handshake; the pong we sent kept
// the connection healthy through both echoes above
check('connection alive after server ping', $ws->isConnected());

$ws->close();
check('closed state after close()', $ws->isConnected(), false);
stopEchoServer($server);


// *
// *  DoS guard: a peer reply larger than max_message_size is rejected
// *  rather than allocated. The echo server reflects our oversized
// *  payload back; the tiny cap must make receive() throw.
// *

$port++;
$server = spawnEchoServer($port);

$guarded  = new WebSocketClient("ws://127.0.0.1:$port/", ['timeout' => 5, 'max_message_size' => 1024]);
$guarded->send(str_repeat('x', 4096));
$rejected = false;
try {
    $guarded->receive();
} catch (\GigaionLLC\NanoPHP\Util\WebSocketClientException $e) {
    $rejected = strpos($e->getMessage(), 'max_message_size') !== false;
}
check('oversized incoming message rejected', $rejected);
stopEchoServer($server);


// *
// *  DoS guards: a hostile server can neither flood the handshake with
// *  headers nor stall the client forever in the middle of a frame
// *

$port++;
$server = spawnEchoServer($port);

$flooded = null;
try {
    new WebSocketClient("ws://127.0.0.1:$port/huge-headers", ['timeout' => 5]);
} catch (\GigaionLLC\NanoPHP\Util\WebSocketClientException $e) {
    $flooded = $e->getMessage();
}
check('oversized handshake headers rejected', $flooded, 'WebSocket handshake response headers too large');

$staller = new WebSocketClient("ws://127.0.0.1:$port/", ['timeout' => 1, 'frame_timeout' => 2]);
$staller->send('__stall__');
$started = microtime(true);
$stalled = null;
try {
    // The first read may be the server's ping; keep reading until the
    // stalled frame makes receive() throw
    for ($i = 0; $i < 5; $i++) {
        $staller->receive();
    }
} catch (\GigaionLLC\NanoPHP\Util\WebSocketClientException $e) {
    $stalled = $e->getMessage();
}
$elapsed = microtime(true) - $started;
check('stalled frame ends with an error', $stalled, 'Timed out waiting for the rest of a WebSocket frame');
check('stalled frame gives up within frame_timeout', $elapsed < 5.0);
check('connection closed after a stalled frame', $staller->isConnected(), false);
stopEchoServer($server);


// *
// *  NanoIPC framing: bounded, looped reads (in-process TCP peer; the
// *  responses are queued before the request is sent)
// *

function ipcPeer(): array
{
    $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    $address  = stream_socket_get_name($listener, false);
    $ipc_port = (int) substr($address, strrpos($address, ':') + 1);

    return [$listener, $ipc_port];
}

[$listener, $ipc_port] = ipcPeer();
$ipc = new \GigaionLLC\NanoPHP\NanoIPC('tcp', ['127.0.0.1', $ipc_port], ['timeout' => 5]);
check('NanoIPC open()', $ipc->open());
$peer = stream_socket_accept($listener, 5);
$ipc_body = json_encode(['count' => '42', 'unchecked' => '0']);
fwrite($peer, pack('N', strlen($ipc_body)) . $ipc_body);
check('NanoIPC reads a framed response', $ipc->block_count(), ['count' => '42', 'unchecked' => '0']);
fclose($peer);
$ipc->close();
fclose($listener);

// A peer announcing a ~4 GiB frame must not make the client allocate it
[$listener, $ipc_port] = ipcPeer();
$ipc = new \GigaionLLC\NanoPHP\NanoIPC('tcp', ['127.0.0.1', $ipc_port], ['timeout' => 5]);
$ipc->open();
$peer = stream_socket_accept($listener, 5);
fwrite($peer, pack('N', 0xFFFFFFF0) . 'xx');
check('NanoIPC rejects an oversized frame length', $ipc->block_count(), false);
check('NanoIPC oversized frame error', strpos((string) $ipc->error, 'exceeds max_response_size') !== false);
fclose($peer);
fclose($listener);

// A frame above a configured cap is rejected too
[$listener, $ipc_port] = ipcPeer();
$ipc = new \GigaionLLC\NanoPHP\NanoIPC('tcp', ['127.0.0.1', $ipc_port], ['timeout' => 5, 'max_response_size' => 16]);
$ipc->open();
$peer = stream_socket_accept($listener, 5);
fwrite($peer, pack('N', strlen($ipc_body)) . $ipc_body);
check('NanoIPC honours max_response_size', $ipc->block_count(), false);
fclose($peer);
fclose($listener);

// A truncated frame is an error, not a silently short response
[$listener, $ipc_port] = ipcPeer();
$ipc = new \GigaionLLC\NanoPHP\NanoIPC('tcp', ['127.0.0.1', $ipc_port], ['timeout' => 2]);
$ipc->open();
$peer = stream_socket_accept($listener, 5);
fwrite($peer, pack('N', 100) . substr($ipc_body, 0, 10));
stream_socket_shutdown($peer, STREAM_SHUT_WR); // EOF after 10 of 100 bytes
check('NanoIPC truncated frame is an error', [$ipc->block_count(), $ipc->error], [false, 'Unable to receive response']);
fclose($peer);
fclose($listener);


// *
// *  NanoWS wrapper (Nano node subscription protocol shape)
// *

// Fresh server on a fresh port: even after waiting for the old process to
// exit, lingering TIME_WAIT sockets can make a same-port rebind flaky
$port++;
$server = spawnEchoServer($port);

$nano_ws = new NanoWS('ws', '127.0.0.1', $port);
check('NanoWS open()', $nano_ws->open());

// The echo server reflects the subscription request; listen() decodes it
$id = $nano_ws->subscribe('confirmation', ['accounts' => ['nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3']], true);
$echo = $nano_ws->listen();

check('subscribe message well-formed', [
    $echo['action'],
    $echo['topic'],
    $echo['id'],
    $echo['ack'],
    $echo['options']['accounts'][0]
], [
    'subscribe',
    'confirmation',
    $id,
    true,
    'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'
]);

$id = $nano_ws->keepalive();
$echo = $nano_ws->listen();
check('keepalive ping', [$echo['action'], $echo['id']], ['ping', $id]);

$nano_ws->close();
stopEchoServer($server);


// *

echo "\n";
if ($failures > 0) {
    echo "$failures TEST(S) FAILED\n";
    exit(1);
}
echo "ALL WEBSOCKET TESTS PASSED\n";
