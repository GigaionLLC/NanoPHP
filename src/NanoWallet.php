<?php

namespace GigaionLLC\NanoPHP;

use \Exception;

class NanoWalletException extends Exception{}

/**
 * High-level Nano wallet built on NanoRPC + NanoBlock + NanoTool.
 *
 * Feature parity with the atto Go client (https://github.com/codesoap/atto):
 * seed generation, address derivation, receiving receivables (including
 * opening unopened accounts), sending by NANO amount, representative
 * management, node-sourced proof of work with the lower receive
 * difficulty, and verification of account_info responses against the
 * frontier block so a malicious or compromised node cannot lie about
 * balances or representatives.
 *
 * Example:
 *   $rpc    = new NanoRPC('http', 'localhost', 7076);
 *   $wallet = NanoWallet::fromSeed($rpc, $seed, 0);
 *
 *   echo $wallet->address();
 *   $wallet->receiveAll();                       // pull in receivables
 *   echo $wallet->balance();                     // raw
 *   $hash = $wallet->send('0.1', $destination);  // amount in NANO
 */
class NanoWallet
{
    // Work difficulty thresholds
    // https://docs.nano.org/integration-guides/work-generation/#difficulty-thresholds
    const WORK_SEND    = 'fffffff800000000'; // send and change blocks
    const WORK_RECEIVE = 'fffffe0000000000'; // receive and open blocks

    // Used when opening an account, changeable afterwards (atto's default)
    const DEFAULT_REPRESENTATIVE = 'nano_11pb5aa6uirs9hoqsg4swnzyehoiqowj94kdpthwkhwufmtd6a11xx35iron';

    private $rpc;
    private $workRpc;
    private $privateKey;
    private $publicKey;
    private $account;
    private $options;

    /** @var ?array Verified chain state: frontier, representative, balance */
    private $info = null;
    private $infoFetched = false;


    // *
    // *  Construction
    // *

    /**
     * @param array $options Recognized keys:
     *   representative     account used when opening (default: DEFAULT_REPRESENTATIVE)
     *   verify_info        verify account_info against the frontier block (default: true)
     *   work_source        'node', 'local' or 'node_fallback' (default: 'node')
     *   work_rpc           separate NanoRPC instance for work_generate (e.g. a work server)
     */
    private function __construct(NanoRPC $rpc, string $private_key, array $options = [])
    {
        $this->rpc        = $rpc;
        $this->privateKey = strtoupper($private_key);
        $this->publicKey  = NanoTool::private2public($private_key);
        $this->account    = NanoTool::public2account($this->publicKey);

        $this->options = array_merge([
            'representative' => self::DEFAULT_REPRESENTATIVE,
            'verify_info'    => true,
            'work_source'    => 'node',
            'work_rpc'       => null
        ], $options);

        $this->workRpc = $this->options['work_rpc'] ?? $rpc;

        if (!in_array($this->options['work_source'], ['node', 'local', 'node_fallback'])) {
            throw new NanoWalletException("Invalid work source: {$this->options['work_source']}");
        }
        if (!NanoTool::account2public($this->options['representative'], false)) {
            throw new NanoWalletException("Invalid representative: {$this->options['representative']}");
        }
    }

    public static function fromSeed(NanoRPC $rpc, string $seed, int $index = 0, array $options = []): self
    {
        $keys = NanoTool::seed2keys($seed, $index);

        return new self($rpc, $keys[0], $options);
    }

    public static function fromPrivateKey(NanoRPC $rpc, string $private_key, array $options = []): self
    {
        return new self($rpc, $private_key, $options);
    }

    /** Generate a new random 64-character hexadecimal seed */
    public static function newSeed(): string
    {
        return strtoupper(bin2hex(random_bytes(32)));
    }


    // *
    // *  Account identity
    // *

    public function address(): string
    {
        return $this->account;
    }

    public function publicKey(): string
    {
        return $this->publicKey;
    }


    // *
    // *  Account state
    // *

    /**
     * Fetch (and by default verify) the account's chain state.
     * Returns null if the account has not been opened yet.
     *
     * Verification mirrors atto: the frontier block is fetched with
     * block_info, its hash is recomputed locally, its signature is
     * checked, and its fields are compared against the account_info
     * response. A node that lies about balance, frontier or
     * representative is detected this way.
     */
    public function accountInfo(bool $refresh = false): ?array
    {
        if ($this->infoFetched && !$refresh) {
            return $this->info;
        }

        $response = $this->rpc->account_info([
            'account'        => $this->account,
            'representative' => 'true'
        ]);

        if ($response === false) {
            if ($this->rpc->error == 'Account not found') {
                $this->info = null;
                $this->infoFetched = true;

                return null;
            }

            throw new NanoWalletException("account_info failed: {$this->rpc->error}");
        }

        $info = [
            'frontier'       => strtoupper($response['frontier']),
            'representative' => $response['representative'],
            'balance'        => $response['balance']
        ];

        if ($this->options['verify_info']) {
            $this->verifyInfo($info);
        }

        $this->info = $info;
        $this->infoFetched = true;

        return $this->info;
    }

    private function verifyInfo(array $info): void
    {
        $response = $this->rpc->block_info([
            'json_block' => 'true',
            'hash'       => $info['frontier']
        ]);

        if ($response === false) {
            throw new NanoWalletException("block_info failed: {$this->rpc->error}");
        }

        $contents = $response['contents'];

        if ($contents['type'] != 'state') {
            // Legacy frontier (pre-2018 account with no state blocks yet):
            // hashing rules differ per legacy type, skip deep verification
            return;
        }

        $hash = NanoTool::hashHexs([
            NanoTool::PREAMBLE_HEX,
            NanoTool::account2public($contents['account']),
            strtoupper($contents['previous']),
            NanoTool::account2public($contents['representative']),
            NanoTool::dec2hex($contents['balance'], 16),
            strtoupper($contents['link'])
        ]);

        if ($hash != $info['frontier'] ||
            $contents['balance'] != $info['balance'] ||
            $contents['representative'] != $info['representative']
        ) {
            throw new NanoWalletException('Account info has been manipulated: frontier block does not match');
        }

        // Epoch blocks are signed by the network's epoch signer instead of
        // the account itself; their link starts with ASCII "epoch"
        if (strpos(strtoupper($contents['link']), '65706F6368') === 0) {
            return;
        }

        if (NanoTool::validSign($hash, $contents['signature'], $contents['account']) === false) {
            throw new NanoWalletException('Account info has been manipulated: invalid frontier signature');
        }
    }

    /**
     * List confirmed receivable (pending) blocks.
     * Returns an array of ['hash' => ..., 'amount' => raw, 'source' => account].
     */
    public function receivables(): array
    {
        $response = $this->rpc->receivable([
            'account'                => $this->account,
            'include_only_confirmed' => 'true',
            'source'                 => 'true'
        ]);

        if ($response === false) {
            throw new NanoWalletException("receivable failed: {$this->rpc->error}");
        }

        $receivables = [];

        // The node returns "" instead of {} when nothing is receivable
        // (nano-node issue #3161)
        if (!empty($response['blocks']) && is_array($response['blocks'])) {
            foreach ($response['blocks'] as $hash => $block) {
                $receivables[] = [
                    'hash'   => strtoupper($hash),
                    'amount' => $block['amount'],
                    'source' => $block['source']
                ];
            }
        }

        return $receivables;
    }

    /**
     * Account balance in raw. By default receivables are pulled in
     * first, like atto's balance subcommand.
     */
    public function balance(bool $receive = true): string
    {
        if ($receive) {
            $this->receiveAll();
        } else {
            $this->accountInfo(true);
        }

        return $this->info['balance'] ?? '0';
    }


    // *
    // *  Block-producing operations
    // *

    /**
     * Receive every confirmed receivable block, opening the account
     * with the configured representative if necessary.
     * Returns one entry per processed block:
     * ['hash' => new block, 'received' => source block, 'amount' => raw].
     */
    public function receiveAll(): array
    {
        $this->accountInfo(true);

        $processed = [];

        foreach ($this->receivables() as $receivable) {
            $builder = new NanoBlock($this->privateKey);

            if ($this->info === null) {
                // First block of the account
                $builder->setWork($this->generateWork($this->publicKey, self::WORK_RECEIVE));
                $block = $builder->open(
                    $receivable['hash'],
                    $receivable['amount'],
                    $this->options['representative']
                );
                $balance = $receivable['amount'];
            } else {
                $builder->setPrev($this->info['frontier'], $this->prevStub());
                $builder->setWork($this->generateWork($this->info['frontier'], self::WORK_RECEIVE));
                $block = $builder->receive($receivable['hash'], $receivable['amount']);
                $balance = $block['balance'];
            }

            $hash = $this->process($block, 'receive', $builder->blockId);

            $this->info = [
                'frontier'       => $hash,
                'representative' => $block['representative'],
                'balance'        => $balance
            ];
            $this->infoFetched = true;

            $processed[] = [
                'hash'     => $hash,
                'received' => $receivable['hash'],
                'amount'   => $receivable['amount']
            ];
        }

        return $processed;
    }

    /**
     * Send funds. The amount is interpreted in the given denomination
     * ('NANO' by default, like atto; use 'raw' for raw). Returns the
     * hash of the published send block.
     */
    public function send(string $amount, string $recipient, string $denomination = 'NANO'): string
    {
        if ($denomination == 'raw') {
            if (!ctype_digit($amount)) {
                throw new NanoWalletException("Invalid raw amount: $amount");
            }
            $raw = $amount;
        } else {
            $raw = NanoTool::den2raw($amount, $denomination);
        }

        if (!NanoTool::account2public($recipient, false)) {
            throw new NanoWalletException("Invalid recipient: $recipient");
        }

        $this->requireOpenAccount();

        if (bccomp($raw, '1') < 0) {
            throw new NanoWalletException("Invalid send amount: $raw raw");
        }
        if (bccomp($this->info['balance'], $raw) < 0) {
            throw new NanoWalletException("Insufficient balance: have {$this->info['balance']} raw, need $raw raw");
        }

        $builder = new NanoBlock($this->privateKey);
        $builder->setPrev($this->info['frontier'], $this->prevStub());
        $builder->setWork($this->generateWork($this->info['frontier'], self::WORK_SEND));
        $block = $builder->send($recipient, $raw);

        $hash = $this->process($block, 'send', $builder->blockId);

        $this->info['frontier'] = $hash;
        $this->info['balance']  = $block['balance'];

        return $hash;
    }

    /** Current representative of the account */
    public function representative(): string
    {
        $this->requireOpenAccount();

        return $this->info['representative'];
    }

    /**
     * Publish a change block that sets a new representative.
     * Returns the hash of the published block.
     */
    public function changeRepresentative(string $representative): string
    {
        if (!NanoTool::account2public($representative, false)) {
            throw new NanoWalletException("Invalid representative: $representative");
        }

        $this->requireOpenAccount();

        $builder = new NanoBlock($this->privateKey);
        $builder->setPrev($this->info['frontier'], $this->prevStub());
        $builder->setWork($this->generateWork($this->info['frontier'], self::WORK_SEND));
        $block = $builder->change($representative);

        $hash = $this->process($block, 'change', $builder->blockId);

        $this->info['frontier']       = $hash;
        $this->info['representative'] = $representative;

        return $hash;
    }


    // *
    // *  Work
    // *

    /**
     * Obtain proof of work for a hash at the given difficulty,
     * honoring the configured work source.
     */
    public function generateWork(string $hash, string $difficulty): string
    {
        switch ($this->options['work_source']) {
            case 'local':
                return $this->generateWorkLocal($hash, $difficulty);

            case 'node_fallback':
                try {
                    return $this->generateWorkNode($hash, $difficulty);
                } catch (NanoWalletException $e) {
                    return $this->generateWorkLocal($hash, $difficulty);
                }

            case 'node':
            default:
                return $this->generateWorkNode($hash, $difficulty);
        }
    }

    private function generateWorkNode(string $hash, string $difficulty): string
    {
        $response = $this->workRpc->work_generate([
            'hash'       => $hash,
            'difficulty' => $difficulty
        ]);

        if ($response === false) {
            throw new NanoWalletException("work_generate failed: {$this->workRpc->error}");
        }

        return $response['work'];
    }

    private function generateWorkLocal(string $hash, string $difficulty): string
    {
        // Pure PHP hashing: fine at low difficulties, but expect hours
        // at the mainnet send threshold; prefer a node or work server
        return strtolower(NanoTool::work($hash, $difficulty));
    }


    // *
    // *  Internals
    // *

    private function requireOpenAccount(): void
    {
        $this->accountInfo();

        if ($this->info === null) {
            throw new NanoWalletException('Account has not been opened yet (no blocks). Receive funds first.');
        }
    }

    /** Previous-block array for NanoBlock::setPrev from verified info */
    private function prevStub(): array
    {
        return [
            'type'           => 'state',
            'account'        => $this->account,
            'previous'       => '',
            'representative' => $this->info['representative'],
            'balance'        => $this->info['balance'],
            'link'           => '',
            'signature'      => '',
            'work'           => ''
        ];
    }

    private function process(array $block, string $subtype, string $expected_hash): string
    {
        $response = $this->rpc->process([
            'json_block' => 'true',
            'subtype'    => $subtype,
            'block'      => $block
        ]);

        if ($response === false) {
            throw new NanoWalletException("process failed: {$this->rpc->error}");
        }

        $hash = strtoupper($response['hash'] ?? '');

        if ($hash != $expected_hash) {
            throw new NanoWalletException("Node confirmed unexpected block hash: $hash (expected $expected_hash)");
        }

        return $hash;
    }
}
