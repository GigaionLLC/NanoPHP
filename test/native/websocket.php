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
