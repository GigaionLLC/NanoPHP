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
