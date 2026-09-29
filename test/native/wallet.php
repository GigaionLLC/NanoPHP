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

// Per-run cache for the mock node's precomputed ledger (see mock-wallet-node.php)
$mock_ledger_cache = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'nanophp-mock-ledger-' . bin2hex(random_bytes(6));
register_shutdown_function(function () use ($mock_ledger_cache) {
    @unlink($mock_ledger_cache);
});

function spawnMockNode(int $port): void
{
    global $mock_ledger_cache;

    $null = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
    $env  = getenv();
    $env['MOCK_LEDGER_CACHE'] = $mock_ledger_cache;
    $mock = proc_open(
        [PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/mock-wallet-node.php'],
        // Discard the server's request log: an unread pipe fills up and
        // stalls the server once enough requests have been logged
        [1 => ['file', $null, 'w'], 2 => ['file', $null, 'w']],
        $pipes,
        null,
        $env
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

// The mock node only produces real work at a cheap test difficulty
$cheap_work = ['work_difficulty_send' => 'f000000000000000', 'work_difficulty_receive' => 'f000000000000000'];

$wallet = NanoWallet::fromSeed($rpc, str_repeat('0', 64), 0, $cheap_work);

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

$wallet_b = NanoWallet::fromSeed($rpc, str_repeat('F', 64), 0, $cheap_work);

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
// *  nanophp CLI: which saved-node file is trusted
// *  (child processes with a controlled environment; the zero seed is the
// *  public test vector account A that the mock node serves)
// *

function runCli(array $args, array $env, string $stdin): array
{
    // Keep what PHP needs to start and open sockets, drop everything else
    foreach (['PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'COMSPEC'] as $name) {
        if (getenv($name) !== false && !isset($env[$name])) {
            $env[$name] = getenv($name);
        }
    }

    $process = proc_open(
        array_merge([PHP_BINARY, dirname(__DIR__, 2) . '/nanophp'], $args),
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        null,
        $env
    );
    fwrite($pipes[0], $stdin);
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);

    return [$status, $stdout, $stderr];
}

$cli_dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'nanophp-cli-test-' . bin2hex(random_bytes(6));
$cli_tmp = $cli_dir . DIRECTORY_SEPARATOR . 'tmp';
$cli_home = $cli_dir . DIRECTORY_SEPARATOR . 'home';
mkdir($cli_tmp, 0700, true);
mkdir($cli_home, 0700, true);
register_shutdown_function(function () use ($cli_dir, $cli_tmp, $cli_home) {
    @unlink($cli_tmp . DIRECTORY_SEPARATOR . '.nanophp-node');
    @unlink($cli_home . DIRECTORY_SEPARATOR . '.nanophp-node');
    @rmdir($cli_tmp);
    @rmdir($cli_home);
    @rmdir($cli_dir);
});

$zero_seed = str_repeat('0', 64) . "\n";
$mock_url  = "http://127.0.0.1:$port";
$no_node   = 'http://127.0.0.1:1'; // nothing listens here

// Without HOME/USERPROFILE a node file planted in the (shared) temp dir must
// be ignored; the CLI falls back to localhost:7076
file_put_contents($cli_tmp . DIRECTORY_SEPARATOR . '.nanophp-node', "$mock_url\n");
[$status, $stdout] = runCli(['r'], ['TMPDIR' => $cli_tmp, 'TEMP' => $cli_tmp, 'TMP' => $cli_tmp], $zero_seed);
check('CLI without HOME ignores a node file in the temp dir', strpos($stdout, NanoWallet::DEFAULT_REPRESENTATIVE), false);

// NANOPHP_NODE still works without a home directory
[$status, $stdout] = runCli(['r'], ['TMPDIR' => $cli_tmp, 'TEMP' => $cli_tmp, 'TMP' => $cli_tmp, 'NANOPHP_NODE' => $mock_url], $zero_seed);
check('CLI without HOME uses NANOPHP_NODE', trim($stdout), NanoWallet::DEFAULT_REPRESENTATIVE);

// The saved node in the user's own home directory is used
$home_env = ['HOME' => $cli_home, 'USERPROFILE' => $cli_home];
file_put_contents($cli_home . DIRECTORY_SEPARATOR . '.nanophp-node', "$mock_url\n");
@chmod($cli_home . DIRECTORY_SEPARATOR . '.nanophp-node', 0644);
[$status, $stdout] = runCli(['r'], $home_env, $zero_seed);
check('CLI uses the node saved in the home directory', trim($stdout), NanoWallet::DEFAULT_REPRESENTATIVE);

if (PHP_OS_FAMILY !== 'Windows') {
    // ...but not when others could have rewritten it
    chmod($cli_home . DIRECTORY_SEPARATOR . '.nanophp-node', 0666);
    [$status, $stdout, $stderr] = runCli(['r'], $home_env, $zero_seed);
    check('CLI ignores a world-writable saved node file', strpos($stdout, NanoWallet::DEFAULT_REPRESENTATIVE) === false && strpos($stderr, 'ignoring') !== false);
    chmod($cli_home . DIRECTORY_SEPARATOR . '.nanophp-node', 0620);
    [$status, $stdout] = runCli(['r'], $home_env, $zero_seed);
    check('CLI ignores a group-writable saved node file', strpos($stdout, NanoWallet::DEFAULT_REPRESENTATIVE), false);
}


// *
// *  nanophp CLI: errors print one clean line, never a stack trace
// *

[$status, $stdout, $stderr] = runCli(['-y', 's', "1\n", NanoTool::seed2keys(str_repeat('F', 64), 0, true)[2]], ['NANOPHP_NODE' => $mock_url], $zero_seed);
check('CLI rejects an amount with a trailing newline cleanly',
    $status === 1 && strpos($stderr, 'Error: Invalid amount') === 0 && stripos($stdout . $stderr, 'stack trace') === false);


// *
// *  NanoRPCExt wallet_send / wallet_sweep accounting (node wallet
// *  EXTWALLET on the mock: X 5 raw, Y 3 raw, Z 4 raw; sends from Z fail)
// *

$ext = new \GigaionLLC\NanoPHP\NanoRPCExt('http', '127.0.0.1', $port);
$ext_x = NanoTool::public2account(str_repeat('A1', 32));
$ext_y = NanoTool::public2account(str_repeat('B2', 32));
$ext_z = NanoTool::public2account(str_repeat('C3', 32));

// 10 raw to Y, which is itself in the wallet: X gives 5, Y's 3 are
// skipped (self send), Z's 2 fail -> only 5 raw actually sent
$result = $ext->wallet_send(['wallet' => 'EXTWALLET', 'destination' => $ext_y, 'amount' => '10']);
check('wallet_send: successful send reported with its amount',
    $result['balances'][$ext_x] ?? null, ['block' => str_repeat('AB', 32), 'amount' => '5']);
check('wallet_send: self send reports the skipped account\'s share',
    $result['balances'][$ext_y] ?? null, ['notice' => 'Skipped self send', 'amount' => '3']);
check('wallet_send: failed send (node error) is reported as an error',
    [$result['balances'][$ext_z]['error'] ?? null, $result['balances'][$ext_z]['amount'] ?? null, $result['balances'][$ext_z]['reason'] ?? null],
    ['Bad send', '2', 'Insufficient balance']);
check('wallet_send: sent total and shortfall surfaced', [$result['sent'] ?? null, $result['shortfall'] ?? null], ['5', '5']);

$result = $ext->wallet_sweep(['wallet' => 'EXTWALLET', 'destination' => $ext_y]);
check('wallet_sweep: successful send', $result['balances'][$ext_x] ?? null, ['block' => str_repeat('AB', 32), 'amount' => '5']);
check('wallet_sweep: failed send is an error', $result['balances'][$ext_z]['error'] ?? null, 'Bad send');
check('wallet_sweep: sent total', $result['sent'] ?? null, '5');


// *
// *  NanoRPC response size cap
// *

$rpc_capped = new NanoRPC('http', '127.0.0.1', $port, null, ['max_response_size' => 16]);
check('response above max_response_size rejected', $rpc_capped->block_count(), false);
check('response cap error message', $rpc_capped->error, 'Response exceeds max_response_size (16 bytes)');
$rpc_uncapped = new NanoRPC('http', '127.0.0.1', $port, null, ['max_response_size' => null]);
check('max_response_size null disables the cap', $rpc_uncapped->block_count()['count'] ?? null, '42');
check('default cap accepts normal responses', $rpc->block_count()['count'] ?? null, '42');


// *
// *  Node-supplied work is validated before a block is published
// *  (default mainnet thresholds: the mock answers with bogus work)
// *

$wallet_badwork = NanoWallet::fromSeed($rpc, str_repeat('0', 64), 0);
$badwork_error = null;
try {
    $wallet_badwork->send('1', $recipient);
} catch (NanoWalletException $e) {
    $badwork_error = $e->getMessage();
}
check('invalid node work is refused before publishing',
    $badwork_error, 'work_generate returned invalid work (not valid for difficulty fffffff800000000)');
expect_manipulation('invalid work_difficulty option rejected', fn() => NanoWallet::fromSeed($rpc, str_repeat('0', 64), 0, ['work_difficulty_send' => 'fff']));


// *
// *  nanophp CLI: control characters from the node never reach the terminal
// *

[$status, $stdout, $stderr] = runCli(['r'], ['NANOPHP_NODE' => "$mock_url/evil"], $zero_seed);
check('CLI strips control characters from node errors',
    [$status, $stderr], [1, "Error: account_info failed: bad[2J[31mnodespoofed line31m\n"]);


// *

echo "\n";
if ($failures > 0) {
    echo "$failures TEST(S) FAILED\n";
    exit(1);
}
echo "ALL WALLET TESTS PASSED\n";
