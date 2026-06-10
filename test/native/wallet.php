<?php

/**
 * NanoWallet integration test against a local mock node.
 *
 * Spawns test/native/mock-wallet-node.php on 127.0.0.1:17077, exercises
 * the full atto-style workflow (address, verified account info,
 * receivables, receive/open, send, representative change) and checks
 * that the anti-manipulation verification catches a lying node.
 *
 *   php test/native/wallet.php
 */

require __DIR__ . '/../autoload.php';

use GigaionLLC\NanoPHP\NanoRPC;
use GigaionLLC\NanoPHP\NanoTool;
use GigaionLLC\NanoPHP\NanoWallet;
use GigaionLLC\NanoPHP\NanoWalletException;

const NANO_RAW = '1000000000000000000000000000000';

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

// *
// *  Spawn the mock node
// *

$port = 17077;
$mock = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/mock-wallet-node.php'],
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes
);

if (!is_resource($mock)) {
    fwrite(STDERR, "Could not start mock node\n");
    exit(1);
}

register_shutdown_function(function () use ($mock) {
    proc_terminate($mock);
});

// Wait for the server to accept connections
$up = false;
for ($i = 0; $i < 50; $i++) {
    $socket = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 0.2);
    if ($socket) {
        fclose($socket);
        $up = true;
        break;
    }
    usleep(100000);
}
if (!$up) {
    fwrite(STDERR, "Mock node did not come up on port $port\n");
    exit(1);
}

$rpc = new NanoRPC('http', '127.0.0.1', $port);


// *
// *  Seed generation
// *

$seed = NanoWallet::newSeed();
check('newSeed is 64 hex chars', strlen($seed) == 64 && ctype_xdigit($seed));


// *
// *  Account A: opened account with 5 NANO and one 2 NANO receivable
// *

$wallet = NanoWallet::fromSeed($rpc, str_repeat('0', 64), 0);

check('address from zero seed',
    $wallet->address(),
    'nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7'
);

$info = $wallet->accountInfo();
check('verified accountInfo balance', $info['balance'], bcmul('5', NANO_RAW));
check('verified accountInfo representative', $info['representative'], NanoWallet::DEFAULT_REPRESENTATIVE);

$receivables = $wallet->receivables();
check('one receivable listed', count($receivables), 1);
check('receivable amount', $receivables[0]['amount'], bcmul('2', NANO_RAW));

$processed = $wallet->receiveAll();
check('receiveAll processed one block', count($processed), 1);
check('receive published a 64-char hash', strlen($processed[0]['hash']), 64);
check('balance after receive', $wallet->accountInfo()['balance'], bcmul('7', NANO_RAW));

$recipient = NanoTool::seed2keys(str_repeat('F', 64), 0, true)[2];

$send_hash = $wallet->send('1', $recipient);
check('send by NANO amount returns hash', strlen($send_hash), 64);
check('balance after 1 NANO send', $wallet->accountInfo()['balance'], bcmul('6', NANO_RAW));

$wallet->send('1000', $recipient, 'raw');
check('send by raw amount', $wallet->accountInfo()['balance'], bcsub(bcmul('6', NANO_RAW), '1000'));

try {
    $wallet->send('100000', $recipient);
    check('overdraft send throws', false);
} catch (NanoWalletException $e) {
    check('overdraft send throws', true);
}

$new_rep = 'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3';
$change_hash = $wallet->changeRepresentative($new_rep);
check('changeRepresentative returns hash', strlen($change_hash), 64);
check('representative updated', $wallet->representative(), $new_rep);


// *
// *  Account B: unopened account, first receive must open it
// *

$wallet_b = NanoWallet::fromSeed($rpc, str_repeat('F', 64), 0);

check('unopened accountInfo is null', $wallet_b->accountInfo(), null);

try {
    $wallet_b->send('1', $wallet->address());
    check('send from unopened account throws', false);
} catch (NanoWalletException $e) {
    check('send from unopened account throws', true);
}

$processed = $wallet_b->receiveAll();
check('first receive opens the account', count($processed), 1);
check('opened balance', $wallet_b->accountInfo()['balance'], bcmul('1', NANO_RAW));
check('opened with default representative',
    $wallet_b->representative(),
    NanoWallet::DEFAULT_REPRESENTATIVE
);


// *
// *  Account C: the node lies about the balance
// *

$wallet_c = NanoWallet::fromSeed($rpc, str_repeat('1', 64), 0);

try {
    $wallet_c->accountInfo();
    check('manipulated account info detected', false);
} catch (NanoWalletException $e) {
    check('manipulated account info detected',
        strpos($e->getMessage(), 'manipulated') !== false
    );
}

// With verification off, the lie goes through (proves the check is real)
$wallet_c2 = NanoWallet::fromSeed($rpc, str_repeat('1', 64), 0, ['verify_info' => false]);
check('verification can be disabled', $wallet_c2->accountInfo()['balance'], bcmul('6', NANO_RAW));


// *

echo "\n";
if ($failures > 0) {
    echo "$failures TEST(S) FAILED\n";
    exit(1);
}
echo "ALL WALLET TESTS PASSED\n";
