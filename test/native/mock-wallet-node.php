<?php

// Nano node RPC emulator with a small consistent ledger, for NanoWallet
// integration tests:
//   php -S 127.0.0.1:17077 test/native/mock-wallet-node.php
//
// Ledger:
//  - Account A (zero seed, index 0): opened with 5 NANO, one receivable
//    of 2 NANO waiting. Frontier is a genuinely signed open block.
//  - Account B (seed FF..FF, index 0): unopened, one receivable of 1 NANO.
//  - Account C (seed 11..11, index 0): the node lies about its state
//    (serves A's frontier with a tampered balance) to exercise the
//    anti-manipulation check.
//  - Account D (seed 22..22): the node claims the frontier is a legacy
//    (non-state) block, lies about the balance and offers a receivable
//    whose hash is an attacker's public key (the verifyInfo bypass that
//    made a receive sign away the whole balance).
//  - Account E (seed 33..33): fake epoch frontier, huge balance, bogus
//    signature.
//  - Account F (seed 44..44): state frontier for F signed by another key.
//  - Account G (seed 55..55): genuine epoch v2 frontier, signed by a test
//    epoch signer (seed 66..66) that the test passes via epoch_signers.
//
// process requests are validated for real: the block hash is recomputed
// and the signature verified before a hash is returned.

require __DIR__ . '/../autoload.php';

use GigaionLLC\NanoPHP\NanoTool;
use GigaionLLC\NanoPHP\NanoBlock;
use GigaionLLC\NanoPHP\NanoWallet;

const NANO_RAW = '1000000000000000000000000000000';

$keys_a = NanoTool::seed2keys(str_repeat('0', 64), 0, true);
$keys_b = NanoTool::seed2keys(str_repeat('F', 64), 0, true);
$keys_c = NanoTool::seed2keys(str_repeat('1', 64), 0, true);

// Account A's frontier: a real, signed open block receiving 5 NANO
$builder = new NanoBlock($keys_a[0]);
$builder->setWork('0000000000000000');
$frontier_block = $builder->open(
    str_repeat('AB', 32),
    bcmul('5', NANO_RAW),
    NanoWallet::DEFAULT_REPRESENTATIVE
);
$frontier_hash = $builder->blockId;

const EPOCH_V2_LINK = '65706F636820763220626C6F636B000000000000000000000000000000000000';

$keys_d = NanoTool::seed2keys(str_repeat('2', 64), 0, true);
$keys_e = NanoTool::seed2keys(str_repeat('3', 64), 0, true);
$keys_f = NanoTool::seed2keys(str_repeat('4', 64), 0, true);
$keys_g = NanoTool::seed2keys(str_repeat('5', 64), 0, true);
$keys_epoch = NanoTool::seed2keys(str_repeat('6', 64), 0, true);
$keys_attacker = NanoTool::seed2keys(str_repeat('7', 64), 0, true);

// Build a state block for an account, signed with $signer_private
function mock_state_block(array $account_keys, string $previous, string $balance, string $link, string $signer_private): array
{
    $hash = NanoTool::hashHexs([
        NanoTool::PREAMBLE_HEX,
        $account_keys[1],
        $previous,
        NanoTool::account2public(NanoWallet::DEFAULT_REPRESENTATIVE),
        NanoTool::dec2hex($balance, 16),
        $link
    ]);

    return ['hash' => $hash, 'contents' => [
        'type'           => 'state',
        'account'        => $account_keys[2],
        'previous'       => $previous,
        'representative' => NanoWallet::DEFAULT_REPRESENTATIVE,
        'balance'        => $balance,
        'link'           => $link,
        'signature'      => NanoTool::sign($hash, $signer_private),
        'work'           => '0000000000000000'
    ]];
}

$fake_epoch_e = mock_state_block($keys_e, str_repeat('E0', 32), bcmul('1000000', NANO_RAW), EPOCH_V2_LINK, $keys_attacker[0]);
$fake_epoch_e['contents']['signature'] = str_repeat('0', 128);

$foreign_signed_f = mock_state_block($keys_f, str_repeat('F0', 32), bcmul('5000000', NANO_RAW), str_repeat('0', 64), $keys_attacker[0]);

$epoch_g = mock_state_block($keys_g, str_repeat('A0', 32), bcmul('3', NANO_RAW), EPOCH_V2_LINK, $keys_epoch[0]);

// account => [account_info response, frontier block contents]
$scenarios = [
    $keys_d[2] => [
        ['frontier' => str_repeat('D0', 32), 'representative' => NanoWallet::DEFAULT_REPRESENTATIVE, 'balance' => '0', 'block_count' => '1'],
        ['type' => 'send']
    ],
    $keys_e[2] => [
        ['frontier' => $fake_epoch_e['hash'], 'representative' => NanoWallet::DEFAULT_REPRESENTATIVE, 'balance' => $fake_epoch_e['contents']['balance'], 'block_count' => '2'],
        $fake_epoch_e['contents']
    ],
    $keys_f[2] => [
        ['frontier' => $foreign_signed_f['hash'], 'representative' => NanoWallet::DEFAULT_REPRESENTATIVE, 'balance' => $foreign_signed_f['contents']['balance'], 'block_count' => '2'],
        $foreign_signed_f['contents']
    ],
    $keys_g[2] => [
        ['frontier' => $epoch_g['hash'], 'representative' => NanoWallet::DEFAULT_REPRESENTATIVE, 'balance' => $epoch_g['contents']['balance'], 'block_count' => '2'],
        $epoch_g['contents']
    ],
];

$scenario_frontiers = [];
foreach ($scenarios as $scenario) {
    $scenario_frontiers[$scenario[0]['frontier']] = $scenario[1];
}

// Optional HTTP Basic Auth gate: start the server with MOCK_BASIC_AUTH set
// to "user:pass" to require matching credentials on every request
$required_auth = getenv('MOCK_BASIC_AUTH');
if ($required_auth !== false && $required_auth !== '') {
    $given = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($given !== 'Basic ' . base64_encode($required_auth)) {
        header('WWW-Authenticate: Basic realm="mock-node"');
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
}

$request = json_decode(file_get_contents('php://input'), true);

header('Content-Type: application/json');

switch ($request['action'] ?? '') {
    case 'account_info':
        if ($request['account'] == $keys_a[2]) {
            echo json_encode([
                'frontier'       => $frontier_hash,
                'representative' => $frontier_block['representative'],
                'balance'        => $frontier_block['balance'],
                'block_count'    => '1'
            ]);
        } elseif (isset($scenarios[$request['account']])) {
            echo json_encode($scenarios[$request['account']][0]);
        } elseif ($request['account'] == $keys_c[2]) {
            // Lying node: real frontier, tampered balance
            echo json_encode([
                'frontier'       => $frontier_hash,
                'representative' => $frontier_block['representative'],
                'balance'        => bcmul('6', NANO_RAW),
                'block_count'    => '1'
            ]);
        } else {
            echo json_encode(['error' => 'Account not found']);
        }
        break;

    case 'block_info':
        if (strtoupper($request['hash']) == $frontier_hash) {
            echo json_encode([
                'block_account' => $keys_a[2],
                'subtype'       => 'receive',
                'confirmed'     => 'true',
                'contents'      => $frontier_block
            ]);
        } elseif (isset($scenario_frontiers[strtoupper($request['hash'])])) {
            echo json_encode([
                'confirmed' => 'true',
                'contents'  => $scenario_frontiers[strtoupper($request['hash'])]
            ]);
        } else {
            echo json_encode(['error' => 'Block not found']);
        }
        break;

    case 'receivable':
        if ($request['account'] == $keys_a[2]) {
            $blocks = [
                str_repeat('CD', 32) => [
                    'amount' => bcmul('2', NANO_RAW),
                    'source' => 'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'
                ]
            ];
        } elseif ($request['account'] == $keys_b[2]) {
            $blocks = [
                str_repeat('EF', 32) => [
                    'amount' => bcmul('1', NANO_RAW),
                    'source' => $keys_a[2]
                ]
            ];
        } elseif ($request['account'] == $keys_d[2]) {
            // "receivable" whose hash is really the attacker's public key
            $blocks = [$keys_attacker[1] => ['amount' => '1', 'source' => $keys_attacker[2]]];
        } else {
            $blocks = ''; // node quirk: "" instead of {} when empty
        }
        echo json_encode(['blocks' => $blocks]);
        break;

    case 'work_generate':
        echo json_encode([
            'work'       => '2b3d689a4c7ac046',
            'difficulty' => $request['difficulty'] ?? 'fffffff800000000'
        ]);
        break;

    case 'process':
        $block = $request['block'];

        // Like a real node, accept the link as hex or as an account address
        $link = $block['link'];
        if (strpos($link, 'nano_') === 0 || strpos($link, 'xrb_') === 0) {
            $link = NanoTool::account2public($link);
        }

        $hash = NanoTool::hashHexs([
            NanoTool::PREAMBLE_HEX,
            NanoTool::account2public($block['account']),
            strtoupper($block['previous']),
            NanoTool::account2public($block['representative']),
            NanoTool::dec2hex($block['balance'], 16),
            strtoupper($link)
        ]);

        if (NanoTool::validSign($hash, $block['signature'], $block['account']) === false) {
            echo json_encode(['error' => 'Block is invalid']);
        } elseif (empty($block['work'])) {
            echo json_encode(['error' => 'Work is missing']);
        } else {
            echo json_encode(['hash' => $hash]);
        }
        break;

    default:
        echo json_encode(['error' => 'Unknown command']);
}
