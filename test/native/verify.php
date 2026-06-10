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

echo "\n";
if ($failures > 0) {
    echo "$failures TEST(S) FAILED\n";
    exit(1);
}
echo "ALL TESTS PASSED\n";
