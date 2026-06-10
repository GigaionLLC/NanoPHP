<?php

// Minimal Nano node RPC emulator for transport tests:
//   php -S 127.0.0.1:17076 test/native/mock-node.php

$request = json_decode(file_get_contents('php://input'), true);

header('Content-Type: application/json');

switch ($request['action'] ?? '') {
    case 'block_count':
        echo json_encode(['count' => '199361594', 'unchecked' => '0', 'cemented' => '199361594']);
        break;

    case 'account_balance':
        echo json_encode(['balance' => '340282366920938463463374607431768211455', 'pending' => '0', 'receivable' => '0']);
        break;

    default:
        echo json_encode(['error' => 'Unknown command']);
}
