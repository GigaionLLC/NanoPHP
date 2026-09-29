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

function spawnMockNode(int $port): void
{
    $null = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
    $mock = proc_open(
        [PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/mock-wallet-node.php'],
        // Discard the server's request log: an unread pipe fills up and
        // stalls the server once enough requests have been logged
        [1 => ['file', $null, 'w'], 2 => ['file', $null, 'w']],
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
    for ($i = 0; $i < 50; $i++) {
        $socket = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 0.2);
        if ($socket) {
            fclose($socket);
            return;
        }
        usleep(100000);
    }

    fwrite(STDERR, "Mock node did not come up on port $port\n");
    exit(1);
}

$port = 17077;
spawnMockNode($port);

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
// *  Accounts D-G: forged frontiers must never be trusted
// *

function expect_manipulation(string $name, callable $fn): void
{
    try {
        $fn();
        check($name, false);
    } catch (NanoWalletException $e) {
        check($name, true);
    }
}

// D: legacy-type frontier claim + attacker "receivable" (previously a
// receive signed a block that sent the whole balance to the attacker)
$wallet_d = NanoWallet::fromSeed($rpc, str_repeat('2', 64), 0);
expect_manipulation('legacy-type frontier is rejected', fn() => $wallet_d->accountInfo());
expect_manipulation('balance() with legacy-type frontier signs nothing', fn() => $wallet_d->balance());
expect_manipulation('receiveAll() with legacy-type frontier signs nothing', fn() => $wallet_d->receiveAll());

// E: an epoch link does not exempt a frontier from signature verification
$wallet_e = NanoWallet::fromSeed($rpc, str_repeat('3', 64), 0);
expect_manipulation('fake epoch frontier is rejected', fn() => $wallet_e->balance(false));

// F: frontier of this account signed by another key
$wallet_f = NanoWallet::fromSeed($rpc, str_repeat('4', 64), 0);
expect_manipulation('frontier signed by a foreign key is rejected', fn() => $wallet_f->balance(false));

// G: genuine epoch frontier signed by the configured epoch signer
$epoch_signer = NanoTool::seed2keys(str_repeat('6', 64), 0, true)[1];
$wallet_g = NanoWallet::fromSeed($rpc, str_repeat('5', 64), 0, [
    'epoch_signers' => ['65706F636820763220626C6F636B000000000000000000000000000000000000' => $epoch_signer]
]);
check('epoch frontier signed by the epoch signer verifies', $wallet_g->balance(false), bcmul('3', NANO_RAW));

// ...and the same block is rejected with the live signers (wrong signer)
$wallet_g_live = NanoWallet::fromSeed($rpc, str_repeat('5', 64), 0);
expect_manipulation('epoch frontier signed by a non-epoch key is rejected', fn() => $wallet_g_live->balance(false));


// *
// *  NanoRPC redirects: not followed by default; when opted in, never
// *  downgraded to http and never carrying credentials to another origin
// *

$second_port = 17087;
spawnMockNode($second_port);

$auth    = ['Authorization: Basic ' . base64_encode('rpcuser:dummy-test-pass')];
$to_same = 'redirect?to=' . rawurlencode('/');
$to_other = 'redirect?to=' . rawurlencode("http://127.0.0.1:$second_port/");

$rpc_default = new NanoRPC('http', '127.0.0.1', $port, $to_same, ['headers' => $auth]);
check('redirect not followed by default', $rpc_default->block_count(), false);
check('unfollowed redirect reports its status', $rpc_default->status, 307);

$rpc_same = new NanoRPC('http', '127.0.0.1', $port, $to_same, ['headers' => $auth, 'follow_location' => true]);
check('opt-in redirect is followed (same origin, POST kept on 307)', $rpc_same->echo_auth(), [
    'authorization' => 'Basic ' . base64_encode('rpcuser:dummy-test-pass'),
    'method'        => 'POST'
]);

$rpc_cross = new NanoRPC('http', '127.0.0.1', $port, $to_other, ['headers' => $auth, 'follow_location' => true]);
check('cross-origin redirect drops the Authorization header', $rpc_cross->echo_auth(), [
    'authorization' => '',
    'method'        => 'POST'
]);

$rpc_loop = new NanoRPC('http', '127.0.0.1', $port, $to_same, ['follow_location' => true, 'max_redirects' => 0]);
$rpc_loop->block_count();
check('max_redirects is enforced', $rpc_loop->error, 'Too many redirects');

$redirect_allowed = new ReflectionMethod(NanoRPC::class, 'redirectAllowed');
$resolve_redirect = new ReflectionMethod(NanoRPC::class, 'resolveRedirect');
check('https -> http redirect refused', $redirect_allowed->invoke(null, 'https://node.example/api', 'http://evil.example/'), false);
check('https -> https redirect allowed', $redirect_allowed->invoke(null, 'https://node.example/api', 'https://node2.example/'), true);
check('http -> https redirect allowed', $redirect_allowed->invoke(null, 'http://node.example/api', 'https://node.example/api'), true);
check('relative redirect resolved', $resolve_redirect->invoke(null, 'https://node.example:8443/a/b', 'c?x=1'), 'https://node.example:8443/a/c?x=1');
check('protocol-relative redirect keeps scheme', $resolve_redirect->invoke(null, 'https://node.example/a', '//other.example/'), 'https://other.example/');
check('non-http redirect target rejected', $resolve_redirect->invoke(null, 'http://node.example/', 'file:///etc/passwd'), null);


// *

echo "\n";
if ($failures > 0) {
    echo "$failures TEST(S) FAILED\n";
    exit(1);
}
echo "ALL WALLET TESTS PASSED\n";
