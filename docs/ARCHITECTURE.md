# Architecture

How the pieces of NanoPHP fit together, bottom-up.

```
                        ┌─────────────────────────────┐
                        │         NanoWallet          │  atto-style workflows:
                        │ receiveAll / send / balance │  verified account info,
                        │ representative management   │  open-on-first-receive
                        └──────┬───────────┬──────────┘
                               │           │
              ┌────────────────┘           └───────────────┐
              ▼                                            ▼
   ┌─────────────────────┐                      ┌─────────────────────┐
   │      NanoBlock      │                      │       NanoRPC       │
   │ build + sign state  │                      │ JSON over HTTP via  │
   │ blocks (open/recv/  │                      │ PHP streams; magic  │
   │ send/change)        │                      │ __call → RPC action │
   └──────────┬──────────┘                      └──────────┬──────────┘
              │                                            │
              ▼                                            ▼
   ┌─────────────────────┐                      ┌─────────────────────┐
   │      NanoTool       │                      │     NanoRPCExt      │
   │ static helpers: keys│                      │ wallet_sweep,       │
   │ addresses, hashing, │                      │ wallet_send,        │
   │ sign/verify, work,  │                      │ wallet_weight       │
   │ units, BIP39/44     │                      │ (extends NanoRPC)   │
   └────┬───────────┬────┘                      └─────────────────────┘
        │           │
        ▼           ▼
┌──────────────┐ ┌────────────────────┐
│Crypto\Blake2b│ │Crypto\Ed25519Blake2b│
│ RFC 7693,    │ │ RFC 8032 with       │
│ pure PHP     │ │ BLAKE2b-512, bcmath │
└──────────────┘ └────────────────────┘
```

Side classes not in the main flow: `NanoCLI` (wraps the `nano_node` CLI
binary), `NanoIPC` (node IPC over `stream_socket_client`, optional legacy
FlatBuffers preprocessing), `NanoWS` (node WebSocket subscriptions, built on
the bundled `Util\WebSocketClient`, an RFC 6455 client over native streams),
`NanoAPI/*` (generated FlatBuffers message models used by NanoIPC). The
`nanophp` script in the repo root is an atto-style CLI built on `NanoWallet`.

## Layer responsibilities

### Crypto\Blake2b — [src/Crypto/Blake2b.php](../src/Crypto/Blake2b.php)

Pure PHP BLAKE2b (RFC 7693), needed because this PHP build has no blake2b in
`hash_algos()` and no sodium. Each 64-bit word is stored as two 32-bit halves
so additions never overflow PHP's signed 64-bit integers. Supports incremental
hashing (`update`/`digest`), one-shot `hash()`, output lengths 1–64 bytes, and
keyed hashing. Everything Nano does flows through this: account checksums
(5-byte output), block hashes (32), private-key derivation (32), work values
(8), and the signature scheme's internal hash (64).

### Crypto\Ed25519Blake2b — [src/Crypto/Ed25519Blake2b.php](../src/Crypto/Ed25519Blake2b.php)

Nano's signature scheme: RFC 8032 Ed25519 with the internal SHA-512 replaced
by BLAKE2b-512. Standard Ed25519 implementations (libsodium,
`sodium_crypto_sign_*`) are therefore incompatible with Nano. Field and group
arithmetic run on bcmath decimal strings (twisted Edwards extended
coordinates, `bcpowmod` for inversion and square roots). ~10–20 ms per
operation. Not constant-time — acceptable for server-side wallet use, like the
pure-PHP Salt library it replaced.

### NanoTool — [src/NanoTool.php](../src/NanoTool.php)

All-static toolbox translating raw crypto into Nano concepts:

| Group | Functions |
|---|---|
| Keys | `keys`, `seed2keys`, `private2public` |
| Addresses | `public2account`, `account2public`, `string2burn` (base32 alphabet `13456789abcdefghijkmnopqrstuwxyz`, 4 leading zero bits, reversed 5-byte BLAKE2b checksum) |
| Blocks | `hashHexs` (BLAKE2b over concatenated hex fields), `sign`, `validSign` |
| Work | `work` (CPU generation), `validWork`, `mult2diff`, `diff2mult` |
| Units | `den2raw`, `raw2den`, `den2den`, `hex2dec`, `dec2hex` (bcmath, exact at 128 bits) |
| Mnemonics | `mnem2hex`, `hex2mnem` (BIP39 with checksum validation), `mnem2mseed`, `mseed2keys` (BIP44 `m/44'/165'/index'`, SLIP-0010 ed25519) |

The BIP39 English wordlist is bundled at `src/Util/bip39-english.txt`.

### NanoBlock — [src/NanoBlock.php](../src/NanoBlock.php)

Stateful builder for signed state blocks. Constructed with a private key;
`setPrev()` (or `autoPrev(true)` for chains) supplies the previous block,
`setWork()` attaches work, then `open()`/`receive()`/`send()`/`change()`
return a node-ready block array and expose the block hash as `->blockId`.
Balances are exact bcmath decimal strings end to end.

### NanoRPC / NanoRPCExt — [src/NanoRPC.php](../src/NanoRPC.php), [src/NanoRPCExt.php](../src/NanoRPCExt.php)

`NanoRPC` posts JSON to a node over native PHP streams (no curl). Any method
call becomes the RPC action: `$rpc->account_info([...])` →
`{"action":"account_info",...}`. Returns the decoded array, or `false` with
`->error`/`->status` populated. Supports the v1 (classic) and v2 (`message_type`
envelope) node APIs. HTTPS requires the openssl extension and fails with a
clear exception without it. `NanoRPCExt` layers multi-account convenience
calls (sweep, send-from-many, weight) on top.

### NanoWallet — [src/NanoWallet.php](../src/NanoWallet.php)

The high-level account workflow ported from the atto Go client; see
[WALLET.md](WALLET.md). Holds one account (seed+index or private key),
verifies node responses, and produces/publishes blocks via `NanoBlock` +
`NanoRPC`, including proof-of-work acquisition at the correct per-subtype
difficulty.

## Trust model

`NanoWallet` does not blindly trust the node. `accountInfo()` re-fetches the
frontier block, recomputes its hash locally, verifies its signature, and
cross-checks balance/representative/frontier against the `account_info`
response (`verify_info` option, on by default — the same defense atto
implements as `ErrAccountManipulated`). `process()` additionally requires the
node to confirm exactly the block hash that was computed locally. Signing
happens locally, always; the seed/private key is never sent anywhere.

## Loading / no Composer

[autoload.php](../autoload.php) at the repo root is a standalone PSR-4
autoloader for `GigaionLLC\NanoPHP\` → `src/`. `require` it and everything works
on a bare PHP build (64-bit, bcmath). `composer.json` exists for those who
want Composer, but nothing in the library depends on it.
