<?php

/**
 * Native crypto verification suite.
 *
 * Runs entirely offline against known vectors: RFC 7693 BLAKE2b vectors,
 * the official Nano key-derivation vector, and real mainnet blocks
 * (genesis open block, a state send block and an epoch v2 block) whose
 * hashes, signatures and work were confirmed on-chain.
 *
 *   php test/native/verify.php
 */

require __DIR__ . '/../autoload.php';

use GigaionLLC\NanoPHP\NanoTool;
use GigaionLLC\NanoPHP\NanoBlock;
use GigaionLLC\NanoPHP\Crypto\Blake2b;
use GigaionLLC\NanoPHP\Crypto\Ed25519Blake2b;

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

// Assert that $fn throws (used to lock in input-validation behavior)
function checkThrows(string $name, callable $fn): void
{
    global $failures;

    try {
        $fn();
        $failures++;
        echo "FAIL  $name (expected an exception, none thrown)\n";
    } catch (\Throwable $e) {
        echo "PASS  $name\n";
    }
}

// *
// *  BLAKE2b (RFC 7693)
// *

check('blake2b-512("")',
    bin2hex(Blake2b::hash('', 64)),
    '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
);

check('blake2b-512("abc") [RFC 7693 appendix A]',
    bin2hex(Blake2b::hash('abc', 64)),
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'
);

check('blake2b-256("")',
    bin2hex(Blake2b::hash('', 32)),
    '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'
);

$data = random_bytes(1000);
$b2b  = new Blake2b(64);
foreach (str_split($data, 37) as $chunk) {
    $b2b->update($chunk);
}
check('blake2b incremental == one-shot', bin2hex($b2b->digest()), bin2hex(Blake2b::hash($data, 64)));


// *
// *  Key derivation (official Nano vector: zero seed, index 0)
// *

$keys = NanoTool::seed2keys(NanoTool::EMPTY32_HEX, 0, true);

check('seed2keys private', $keys[0], '9F0E444C69F77A49BD0BE89DB92C38FE713E0963165CCA12FAF5712D7657120F');
check('seed2keys public',  $keys[1], 'C008B814A7D269A1FA3C6528B19201A24D797912DB9996FF02A1FF356E45552B');
check('seed2keys account', $keys[2], 'nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7');

check('account2public',
    NanoTool::account2public('nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7'),
    'C008B814A7D269A1FA3C6528B19201A24D797912DB9996FF02A1FF356E45552B'
);

check('account2public rejects bad checksum',
    NanoTool::account2public('nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b9'),
    false
);

check('private2public',
    NanoTool::private2public($keys[0]),
    $keys[1]
);

$random = NanoTool::keys(true);
check('keys() roundtrip', NanoTool::account2public($random[2]), $random[1]);


// *
// *  Genesis open block (legacy), on-chain data
// *

$genesis_pub = 'E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA';

check('genesis open block hash',
    NanoTool::hashHexs([$genesis_pub, $genesis_pub, $genesis_pub]),
    '991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'
);

check('genesis on-chain signature verifies',
    NanoTool::validSign(
        '991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948',
        '9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02',
        'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'
    ),
    '991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'
);

check('genesis work valid',
    NanoTool::validWork($genesis_pub, 'ffffffc000000000', '62f05417dd3fb691')
);

check('work below threshold rejected',
    NanoTool::validWork($genesis_pub, 'fffffffff0000000', '62f05417dd3fb691'),
    false
);


// *
// *  State send block (mainnet D2655449..., height 17 of nano_1mikerow...)
// *

$account_pub = NanoTool::account2public('nano_1mikerow9bqzyqo4ejra6ugr1srerq1egwmacerquch3dz1wry7mkrz4768m');

check('state block hash',
    NanoTool::hashHexs([
        NanoTool::PREAMBLE_HEX,
        $account_pub,
        '1774B116D5617FCE0300F8E64C42ACC8781E519A50AD3A2B2084C7E2B0A0C346',
        $account_pub,
        '00000000000000000000000000000000',
        'D4EE1AAEADC3EDA9FA4F1E33B5444CF87BE8CF7AE7D0AA045D8F248226B3F04E'
    ]),
    'D265544938253286CEBAC95C8B192C83D09826D580F4A42AD6D0403CC34059A7'
);

check('state block on-chain signature verifies',
    NanoTool::validSign(
        'D265544938253286CEBAC95C8B192C83D09826D580F4A42AD6D0403CC34059A7',
        '92A3FC0E07AA50B0B524464FE99657E79C769E5EDDC668BC36A60CB2F1E14BD004DE2ABE4E2A9817E822F31D16602D6909515BFA563E74A220A71FD756BF9602',
        'nano_1mikerow9bqzyqo4ejra6ugr1srerq1egwmacerquch3dz1wry7mkrz4768m'
    ) !== false
);

check('state block work valid',
    NanoTool::validWork('1774B116D5617FCE0300F8E64C42ACC8781E519A50AD3A2B2084C7E2B0A0C346', 'ffffffc000000000', '8ca358e47d3805eb')
);

// Epoch v2 block of the same account (link = "epoch v2 block" padded);
// signed by the dedicated epoch v2 signer, so only the hash is asserted here
check('epoch v2 block hash',
    NanoTool::hashHexs([
        NanoTool::PREAMBLE_HEX,
        $account_pub,
        'D265544938253286CEBAC95C8B192C83D09826D580F4A42AD6D0403CC34059A7',
        $account_pub,
        '00000000000000000000000000000000',
        '65706F636820763220626C6F636B000000000000000000000000000000000000'
    ]),
    'B666A6822CA488BCF6290F6097CA18DBD5EAFD96A689557E470DBEF81FF5E4EA'
);

// Its on-chain signature is by the live epoch v2 signer that NanoWallet
// pins, not by the account (fetched once from the live network)
$epoch_v2_sig = '87C9FB0987B5496DCBAE333157E26116C579A0AB376DE933177E7A56CA27458147A5A90BC995C79B0A1BB9E8299D654025150E0755764AD941D50F0B7F970102';
check('epoch v2 block signed by the pinned epoch v2 signer',
    NanoTool::validSign(
        'B666A6822CA488BCF6290F6097CA18DBD5EAFD96A689557E470DBEF81FF5E4EA',
        $epoch_v2_sig,
        NanoTool::public2account(GigaionLLC\NanoPHP\NanoWallet::EPOCH_SIGNERS_LIVE['65706F636820763220626C6F636B000000000000000000000000000000000000'])
    ) !== false
);
check('epoch v2 block not signed by the account itself',
    NanoTool::validSign(
        'B666A6822CA488BCF6290F6097CA18DBD5EAFD96A689557E470DBEF81FF5E4EA',
        $epoch_v2_sig,
        'nano_1mikerow9bqzyqo4ejra6ugr1srerq1egwmacerquch3dz1wry7mkrz4768m'
    ),
    false
);


// *
// *  NanoBlock: build, self-verify signature, big balance handling
// *

$block_builder = new NanoBlock($keys[0]);
$block_builder->autoPrev(true);
$block_builder->setWork('0000000000000000');

$open = $block_builder->open(
    str_repeat('AB', 32),
    '340282366920938463463374607431768211455', // 2^128-1, max raw
    'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'
);

check('NanoBlock open balance is exact decimal string', $open['balance'], '340282366920938463463374607431768211455');
check('NanoBlock open signature verifies',
    NanoTool::validSign($block_builder->blockId, $open['signature'], $keys[2]) !== false
);

$block_builder->setWork('0000000000000000');
$send = $block_builder->send('nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3', '1000000000000000000000000000001');

check('NanoBlock send balance exact', $send['balance'], '340282365920938463463374607431768211454');
check('NanoBlock send signature verifies',
    NanoTool::validSign($block_builder->blockId, $send['signature'], $keys[2]) !== false
);

try {
    $block_builder->setWork('0000000000000000');
    $block_builder->send('nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3', '999999999999999999999999999999999999999');
    check('NanoBlock overdraft throws', false);
} catch (\GigaionLLC\NanoPHP\NanoBlockException $e) {
    check('NanoBlock overdraft throws', true);
}


// *
// *  Denominations, difficulty, conversions
// *

check('den2raw', NanoTool::den2raw('1.5', 'NANO'), '1500000000000000000000000000000');
check('raw2den', NanoTool::raw2den('1500000000000000000000000000000', 'NANO'), '1.5');
check('den2den', NanoTool::den2den('1', 'NANO', 'knano'), '1000');

// Regression: leading/trailing dot and validation. ".5" once produced
// 5 NANO instead of 0.5 (a 10x overspend through the send path).
check('den2raw leading dot .5',  NanoTool::den2raw('.5', 'NANO'),  '500000000000000000000000000000');
check('den2raw 0.5 == .5',       NanoTool::den2raw('0.5', 'NANO'), '500000000000000000000000000000');
check('den2raw trailing dot 5.', NanoTool::den2raw('5.', 'NANO'),  '5000000000000000000000000000000');
check('den2raw 0',               NanoTool::den2raw('0', 'NANO'),   '0');
check('den2raw min raw',         NanoTool::den2raw('0.000000000000000000000000000001', 'NANO'), '1');
checkThrows('den2raw rejects letters',     fn() => NanoTool::den2raw('abc', 'NANO'));
checkThrows('den2raw rejects negative',    fn() => NanoTool::den2raw('-1', 'NANO'));
checkThrows('den2raw rejects sci notation',fn() => NanoTool::den2raw('1e3', 'NANO'));
checkThrows('den2raw rejects double dot',  fn() => NanoTool::den2raw('1.2.3', 'NANO'));
checkThrows('den2raw rejects empty',       fn() => NanoTool::den2raw('', 'NANO'));
checkThrows('den2raw rejects lone dot',    fn() => NanoTool::den2raw('.', 'NANO'));
checkThrows('den2raw rejects sub-raw',     fn() => NanoTool::den2raw('0.0000000000000000000000000000001', 'NANO'));
check('raw2den min raw', NanoTool::raw2den('1', 'NANO'), '0.000000000000000000000000000001');
check('raw2den 0',       NanoTool::raw2den('0', 'NANO'), '0');
checkThrows('raw2den rejects decimal', fn() => NanoTool::raw2den('12.5', 'NANO'));
checkThrows('raw2den rejects letters', fn() => NanoTool::raw2den('abc', 'NANO'));
checkThrows('raw2den rejects negative',fn() => NanoTool::raw2den('-5', 'NANO'));
check('den2raw/raw2den roundtrip max',
    NanoTool::den2raw(NanoTool::raw2den('340282366920938463463374607431768211455', 'NANO'), 'NANO'),
    '340282366920938463463374607431768211455'
);

check('hex2dec', NanoTool::hex2dec('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), '340282366920938463463374607431768211455');
check('dec2hex', NanoTool::dec2hex('340282366920938463463374607431768211455', 16), 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
check('dec2hex zero pad', NanoTool::dec2hex('0', 16), '00000000000000000000000000000000');

check('diff2mult 8x', NanoTool::diff2mult('fffffe0000000000', 'ffffffc000000000'), 8.0);
check('mult2diff 8x', NanoTool::mult2diff('fffffe0000000000', 8.0), 'ffffffc000000000');
check('mult2diff 1/8', NanoTool::mult2diff('ffffffc000000000', 0.125), 'fffffe0000000000');


// *
// *  BIP39/44 mnemonics
// *

$mnemonic = NanoTool::hex2mnem('59B1E39BB400D59B9EFD1C263DE634448751D0CAB90665E6894EB391CE158853');
check('hex2mnem word count', count($mnemonic), 24);
check('mnem2hex roundtrip', NanoTool::mnem2hex($mnemonic), '59B1E39BB400D59B9EFD1C263DE634448751D0CAB90665E6894EB391CE158853');

// BIP39 reference vector (Trezor test vectors, entropy 0x00*16, passphrase TREZOR)
$abandon = NanoTool::hex2mnem('00000000000000000000000000000000');
check('hex2mnem BIP39 vector words',
    implode(' ', $abandon),
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
);
check('mnem2mseed BIP39 vector',
    strtolower(NanoTool::mnem2mseed($abandon, 'TREZOR')),
    'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'
);

$mseed_keys = NanoTool::mseed2keys(NanoTool::mnem2mseed($abandon, 'TREZOR'), 0, true);
check('mseed2keys derives valid account', NanoTool::account2public($mseed_keys[2]), $mseed_keys[1]);

try {
    $bad = $mnemonic;
    $bad[23] = $bad[23] == 'abandon' ? 'ability' : 'abandon';
    NanoTool::mnem2hex($bad);
    check('mnem2hex rejects bad checksum', false);
} catch (\GigaionLLC\NanoPHP\NanoToolException $e) {
    check('mnem2hex rejects bad checksum', true);
}


// *
// *  Burn account, signing roundtrip
// *

$burn = NanoTool::string2burn('nanophp');
check('string2burn has valid checksum', NanoTool::account2public($burn, false));

$msg = strtoupper(bin2hex(random_bytes(32)));
$sig = NanoTool::sign($msg, $keys[0]);
check('sign/validSign roundtrip', NanoTool::validSign($msg, $sig, $keys[2]), $msg);
$bad_sig = substr($sig, 0, 126) . (substr($sig, 126, 2) == '00' ? '01' : '00');
check('validSign rejects tampered signature', NanoTool::validSign($msg, $bad_sig, $keys[2]), false);


// *
// *  Work generation at a low difficulty (fast)
// *

$work = NanoTool::work($genesis_pub, '8000000000000000');
check('generated work validates', NanoTool::validWork($genesis_pub, '8000000000000000', $work));


// *
// *  NanoCLI: no shell injection through option values or names
// *  (PHP itself stands in for the nano_node binary)
// *

$cli = new \GigaionLLC\NanoPHP\NanoCLI(PHP_BINARY);
$payloads = ['x & echo INJECTED_MARKER', 'x; echo INJECTED_MARKER', 'x | echo INJECTED_MARKER',
             'x && echo INJECTED_MARKER', '$(echo INJECTED_MARKER)', '`echo INJECTED_MARKER`'];
$injected = false;
foreach ($payloads as $payload) {
    $out = $cli->version(['account' => $payload]);
    if (strpos(implode("\n", (array) $out) . (string) $cli->error, 'INJECTED_MARKER') !== false) {
        $injected = true;
    }
}
check('NanoCLI option values cannot inject shell commands', $injected, false);
check('NanoCLI benign call still runs the binary', is_array($cli->version()) && $cli->status === 0);
checkThrows('NanoCLI rejects a method name with shell syntax', fn() => $cli->{'version & echo x'}());
checkThrows('NanoCLI rejects an option name with shell syntax', fn() => $cli->version(['a & echo x' => '1']));
checkThrows('NanoCLI rejects an option name with a dash', fn() => $cli->version(['--x' => '1']));


// *
// *  Secrets never appear in exception messages, traces or object dumps
// *  (throwaway values; a trailing newline is the classic trigger)
// *

// Returns [message, trace] of the exception $fn throws ('' if none)
function thrownText(callable $fn): string
{
    try {
        $fn();
    } catch (\Throwable $e) {
        return $e->getMessage() . "\n" . $e->getTraceAsString();
    }
    return '';
}

$secret_seed  = strtoupper(bin2hex(random_bytes(32)));
$secret_key   = strtoupper(bin2hex(random_bytes(32)));
$secret_mseed = strtoupper(bin2hex(random_bytes(64)));
$secret_hex   = strtoupper(bin2hex(random_bytes(16)));
$secret_words = NanoTool::hex2mnem($secret_hex);

$leaks = [
    'seed2keys'      => [fn() => NanoTool::seed2keys($secret_seed . "\n"), $secret_seed],
    'private2public' => [fn() => NanoTool::private2public($secret_key . ' '), $secret_key],
    'public2account' => [fn() => NanoTool::public2account($secret_key . ' '), $secret_key],
    'sign'           => [fn() => NanoTool::sign('AB', $secret_key . "\n"), $secret_key],
    'mseed2keys'     => [fn() => NanoTool::mseed2keys($secret_mseed . "\n"), $secret_mseed],
    'hex2mnem'       => [fn() => NanoTool::hex2mnem($secret_hex . 'Z'), $secret_hex],
    'NanoBlock'      => [fn() => new NanoBlock($secret_key . "\n"), $secret_key],
    'NanoWallet'     => [fn() => \GigaionLLC\NanoPHP\NanoWallet::fromPrivateKey(new \GigaionLLC\NanoPHP\NanoRPC(), $secret_key . "\n"), $secret_key],
];
foreach ($leaks as $name => [$fn, $secret]) {
    $text = thrownText($fn);
    // Traces print the first 15 characters of string arguments by default
    check("$name error omits the secret", $text !== '' && stripos($text, substr($secret, 0, 12)) === false);
}

$typo_words = $secret_words;
$typo_words[5] = 'notabip39word' . $secret_words[5];
$text = thrownText(fn() => NanoTool::mnem2hex($typo_words));
check('mnem2hex error names the position, not the word', strpos($text, 'position 6') !== false && strpos($text, $typo_words[5]) === false);
$text = thrownText(fn() => NanoTool::mnem2mseed($typo_words));
check('mnem2mseed error names the position, not the word', strpos($text, 'position 6') !== false && strpos($text, $typo_words[5]) === false);

$dump_block  = new NanoBlock($secret_key);
$dump_wallet = \GigaionLLC\NanoPHP\NanoWallet::fromPrivateKey(new \GigaionLLC\NanoPHP\NanoRPC(), $secret_key);
ob_start();
var_dump($dump_block, $dump_wallet);
$dumps = ob_get_clean() . print_r($dump_block, true) . print_r($dump_wallet, true);
check('var_dump/print_r of NanoBlock and NanoWallet omit the private key', stripos($dumps, $secret_key) === false);
check('NanoWallet dump still shows the account', strpos($dumps, $dump_wallet->address()) !== false);


// *
// *  Trailing newlines are invalid input, rejected with a clean exception
// *  ("$" in a regex also matches before a final "\n")
// *

foreach (["1\n", "0.1\n", ".5\n", "1\n\n"] as $newline_amount) {
    $caught = null;
    try {
        NanoTool::den2raw($newline_amount, 'NANO');
    } catch (\Throwable $e) {
        $caught = get_class($e);
    }
    check('den2raw rejects ' . json_encode($newline_amount) . ' with NanoToolException', $caught, \GigaionLLC\NanoPHP\NanoToolException::class);
}
check('account2public rejects a trailing newline',
    NanoTool::account2public(substr($keys[2], 0, 64) . "\n"), false);
checkThrows('string2burn rejects a trailing newline', fn() => NanoTool::string2burn("nanophp\n"));
checkThrows('string2burn rejects a newline filling character', fn() => NanoTool::string2burn('nanophp', '1', "1\n"));


// *
// *  Small-order public keys and R values are rejected (the 8 torsion
// *  points; with them S = 0 "signs" arbitrary messages)
// *

$small_order = [
    '0100000000000000000000000000000000000000000000000000000000000000', // identity
    'ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F', // order 2
    '0000000000000000000000000000000000000000000000000000000000000000', // order 4
    '0000000000000000000000000000000000000000000000000000000000000080', // order 4
    '26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05', // order 8
    '26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85', // order 8
    'C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A', // order 8
    'C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA', // order 8
];

// The identity-key forgery from the security review: A = R = identity,
// S = 0 used to verify for any message
$identity_account = NanoTool::public2account($small_order[0]);
$forged_sig = $small_order[0] . str_repeat('0', 64);
check('identity-key forgery rejected (validSign)',
    NanoTool::validSign(strtoupper(bin2hex(random_bytes(32))), $forged_sig, $identity_account), false);

$torsion_forgeries = 0;
$forgery_msg = hex2bin('4E414E4F504850'); // any message
foreach ($small_order as $a_hex) {
    foreach ($small_order as $r_hex) {
        if (Ed25519Blake2b::verify($forgery_msg, hex2bin($r_hex) . str_repeat("\0", 32), hex2bin($a_hex))) {
            $torsion_forgeries++;
        }
    }
}
check('no small-order A/R combination verifies with S = 0', $torsion_forgeries, 0);

// A genuine signature by a real key must not be affected
$real_keys = NanoTool::seed2keys(str_repeat('0', 64), 0, true);
$real_msg  = str_repeat('AB', 32);
check('genuine signature still verifies after small-order checks',
    NanoTool::validSign($real_msg, NanoTool::sign($real_msg, $real_keys[0]), $real_keys[2]), $real_msg);


// *
// *  Fixed-length signing ladder: output must stay byte-identical.
// *  32 deterministic keys/messages (lengths 0..62 bytes); the digest was
// *  produced by the previous variable-length implementation.
// *

$ladder_outputs = '';
$ladder_verified = true;
for ($i = 0; $i < 32; $i++) {
    $ladder_key = Blake2b::hash("nanophp-ladder-key-$i", 32);
    $ladder_msg = substr(Blake2b::hash("nanophp-ladder-msg-$i", 64), 0, $i * 2);
    $ladder_pub = Ed25519Blake2b::publicKey($ladder_key);
    $ladder_sig = Ed25519Blake2b::sign($ladder_msg, $ladder_key);
    $ladder_verified = $ladder_verified && Ed25519Blake2b::verify($ladder_msg, $ladder_sig, $ladder_pub);
    $ladder_outputs .= $ladder_pub . $ladder_sig;
    if ($i === 0) {
        check('ladder vector 0 public key', bin2hex($ladder_pub), '1303101bc612286f430d50df6e81b9f701b48a7a291cbb5c4d69aa9994ac7b90');
        check('ladder vector 0 signature (empty message)', bin2hex($ladder_sig),
            '9fa4453ac7fa60d7e0eaca091014a708bcda49ad2af291a64eb32d25456d116367f3e04239715895abd3c326d423a0ac93355c584ee9eeeedd1f53933815320d');
    }
}
check('32 deterministic keys/signatures identical to the previous implementation',
    hash('sha256', $ladder_outputs), '0d3bea5b8f71613a2d43e5eab5cbe640490394aed37496a30ba3dcb1cd9936b0');
check('32 deterministic signatures verify', $ladder_verified);


// *

echo "\n";
if ($failures > 0) {
    echo "$failures TEST(S) FAILED\n";
    exit(1);
}
echo "ALL TESTS PASSED\n";
