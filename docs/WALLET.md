# NanoWallet

`GigaionLLC\NanoPHP\NanoWallet` is the high-level account workflow, ported from
the [atto](https://github.com/codesoap/atto) Go client so that everything the
old attoPHP/atto-binary bridge did can now be done natively in PHP.

## atto feature mapping

| atto | NanoPHP | Notes |
|---|---|---|
| `atto new` | `NanoWallet::newSeed()` | 64-char hex seed from `random_bytes` |
| `atto address` | `$wallet->address()` | seed + account index → `nano_…` address |
| `atto balance` | `$wallet->balance()` | receives all receivables first, then reports balance (pass `false` to skip receiving) |
| (part of balance) | `$wallet->receivables()`, `$wallet->receiveAll()` | also exposed individually; `receiveAll()` opens unopened accounts with the configured representative |
| `atto representative` | `$wallet->representative()` | reads from verified account info |
| `atto representative REP` | `$wallet->changeRepresentative($rep)` | publishes a change block |
| `atto send AMOUNT RECEIVER` | `$wallet->send($amount, $recipient)` | amount in NANO by default; `'raw'` or any `NanoTool::RAWS` denomination supported |
| `ErrAccountManipulated` check | `verify_info` option (default on) | frontier block re-hashed and signature-verified locally |
| work source local/node/fallback | `work_source` option | `'node'` (default), `'local'`, `'node_fallback'` |
| account index `-a` | `fromSeed($rpc, $seed, $index)` | 0 – 4294967295 |
| `atto-safesign` | not ported | sign offline with `NanoBlock` directly |

A command-line interface with atto-compatible subcommands (including
abbreviations, `-v`, and `NANOPHP_BASIC_AUTH_*` HTTP Basic Authentication
mirroring atto's `ATTO_BASIC_AUTH_*`) is included as [`nanophp`](../nanophp)
in the repo root — see the README for terminal examples.

## Usage

```php
require '/path/to/NanoPHP/autoload.php';

use GigaionLLC\NanoPHP\NanoRPC;
use GigaionLLC\NanoPHP\NanoWallet;

$rpc    = new NanoRPC('http', 'localhost', 7076);
$wallet = NanoWallet::fromSeed($rpc, $seed, 0);   // or ::fromPrivateKey()

echo $wallet->address(), "\n";

// Pull in incoming funds (opens the account on first receive)
foreach ($wallet->receiveAll() as $r) {
    echo "received {$r['amount']} raw in block {$r['hash']}\n";
}

// Balance in raw; convert with NanoTool::raw2den($raw, 'NANO')
echo $wallet->balance(), "\n";

// Send 0.05 NANO
$hash = $wallet->send('0.05', 'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3');

// Representative management
echo $wallet->representative(), "\n";
$wallet->changeRepresentative('nano_11pb5aa6uirs9hoqsg4swnzyehoiqowj94kdpthwkhwufmtd6a11xx35iron');
```

All failures throw `NanoWalletException` with the underlying RPC error in the
message.

### Options (4th argument of the constructors)

| Key | Default | Meaning |
|---|---|---|
| `representative` | atto's default rep | used when opening the account on first receive |
| `verify_info` | `true` | verify `account_info` against the frontier block (below) |
| `work_source` | `'node'` | `'node'` = `work_generate` RPC; `'local'` = pure-PHP CPU work (only sane at low difficulties); `'node_fallback'` = node first, CPU on failure |
| `work_rpc` | the main `NanoRPC` | separate `NanoRPC` instance for `work_generate`, e.g. a dedicated work server |

### Proof of work

Receive/open blocks are requested at the lower receive threshold
(`fffffe0000000000`), sends and representative changes at the full send
threshold (`fffffff800000000`) — the same optimization atto applies, which
makes receives much cheaper for the work provider. Work for the first block
of an account is computed against the public key, afterwards against the
frontier hash.

### The anti-manipulation check

With `verify_info` enabled (default), `accountInfo()` does not take the
node's word for anything it can check itself:

1. `account_info` is fetched, then `block_info` for the reported frontier;
2. the frontier block's state hash is recomputed locally with
   `NanoTool::hashHexs`;
3. the recomputed hash must equal the reported frontier, and the block's
   balance and representative must equal the `account_info` values;
4. the block's signature is verified against the account's public key
   (skipped for epoch blocks, which the network's epoch signer signs, and for
   legacy pre-state frontiers).

A node that reports a wrong balance, frontier, or representative triggers a
`NanoWalletException` ("Account info has been manipulated") instead of a bad
block being built and signed. Additionally, `process` responses must confirm
exactly the locally computed block hash.

### What still requires trust

The node can still lie by *omission* (hide receivables, claim a block was
processed when it wasn't, serve a stale frontier and cause a fork-rejection).
Those are detectable only with multiple independent nodes, which is out of
scope — same as atto.

## Testing

`php test/native/wallet.php` runs the full workflow against
`test/native/mock-wallet-node.php`, a mini node emulator that serves a
genuinely signed ledger (built with the library itself), validates submitted
blocks server-side (hash + signature), and deliberately lies about one
account's balance to prove the manipulation check fires.
