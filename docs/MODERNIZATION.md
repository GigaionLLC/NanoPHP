# Modernization log

Everything changed in the GigaionLLC fork relative to the archived
MikeRow/NanoPHP (last upstream commit 2020). Baseline target: 64-bit PHP 8.1+
with only `bcmath`, no Composer, tested on PHP 8.5.

## Dependencies eliminated

The archived library required five PHP extensions and four Composer packages
for its core. All were removed or replaced:

| Was required | Replaced by |
|---|---|
| `mikerow/salt` (pure-PHP NaCl fork) | `src/Crypto/Ed25519Blake2b.php` + `src/Crypto/Blake2b.php`, written for this fork |
| `ext-blake2` (suggested C extension) | `src/Crypto/Blake2b.php` (pure PHP, RFC 7693) |
| `ext-gmp` | bcmath (`bcadd`/`bcsub`/`bccomp` and `NanoTool::hex2dec`/`dec2hex`) |
| `ext-curl` | PHP streams (`file_get_contents` + `stream_context_create`) in `NanoRPC` |
| `bitwasp/bitcoin-lib` (BIP39 wordlist) | bundled `src/Util/bip39-english.txt` (2048 words) |
| `textalk/websocket` (NanoWS) | bundled `src/Util/WebSocketClient.php` (RFC 6455 over native streams) |
| `ext-mbstring`, `ext-openssl` | not needed (openssl only if you want RPC over https / wss) |
| Composer itself | standalone `autoload.php` at the repo root |

The only remaining external reference is `google/flatbuffers` for `NanoIPC`'s
legacy FlatBuffers preprocessing path (optional at runtime; modern nodes use
JSON over IPC). Everything else in the repository is self-contained.

## Correctness bugs fixed

1. **128-bit balance corruption in `NanoBlock`** — block arrays carried
   `'balance' => hexdec($balance)`, and `open()`/`change()` used
   `dechex($amount)`. Both silently lose precision above 2⁵³ (PHP converts to
   float), i.e. for any realistic raw amount. Balances are now exact decimal
   strings converted with bcmath (`NanoTool::dec2hex`).
2. **`validWork` float comparison** — compared `hexdec()` values of 64-bit
   hex strings as floats; near-threshold values compare wrong. Now a binary
   `strcmp` on big-endian bytes (exact, unsigned).
3. **`work()` used `strcasecmp` on binary data** — case-insensitive comparison
   applied to raw bytes folds `A–Z`/`a–z` byte values together; now `strcmp`.
4. **`mult2diff`/`diff2mult` float precision** — `hexdec`/`dechex` round-trips
   on 64-bit difficulties lose low bits; now computed with bcmath
   (`mult2diff('fffffe0000000000', 8.0)` returns exactly `ffffffc000000000`).
5. **`string2burn` validation typo** — `strlen($filling_char != 1)` (compares
   then takes strlen) accepted invalid filling characters; now a proper regex
   check.
6. **`mnem2hex` accepted bad mnemonics** — the BIP39 checksum was never
   verified; a mistyped word produced a silently wrong seed. The checksum is
   now validated and a `NanoToolException` thrown on mismatch.
7. **`NanoRPC` treated non-JSON responses as success** — `json_decode`
   failure left `error` unset and returned `null`; now returns `false` with
   `error = 'Invalid JSON response from node'`.

## PHP 8.5 compatibility

- Implicit nullable parameters (`string $x = null`) → explicit `?string`
  across `NanoBlock`, `NanoRPC`, `NanoWS`, `NanoIPC` (deprecated since 8.4).
- `$http_response_header` (deprecated in 8.5) → `http_get_last_response_headers()`
  with a fallback for older PHP.
- No dynamic-property or other deprecation warnings under `E_ALL` on 8.5.

## Removed

- `src/Util/Uint.php`, `src/Util/Base.php`, `src/Util/Bin.php` — the old
  SplFixedArray-based byte-juggling helpers. All call sites now use native
  binary strings, `hex2bin`/`bin2hex`, `pack`/`unpack`, and bcmath.
- The Wiki had already been removed upstream; documentation now lives in
  `docs/`, with agent/contributor guidance in `AGENT.md` (`CLAUDE.md` points
  to it).

## Added

- `src/Crypto/Blake2b.php` — pure PHP BLAKE2b ([CRYPTO.md](CRYPTO.md)).
- `src/Crypto/Ed25519Blake2b.php` — Nano's Ed25519-BLAKE2b ([CRYPTO.md](CRYPTO.md)).
- `src/NanoWallet.php` — high-level wallet with atto feature parity
  ([WALLET.md](WALLET.md)).
- `src/Util/WebSocketClient.php` — bundled RFC 6455 WebSocket client.
- `nanophp` — atto-style command line wallet (`new`, `node`, `address`,
  `balance`, `receive`, `representative`, `send`, plus `-v`/`-h`; subcommands
  abbreviate to their first letters like atto). HTTP Basic Authentication is
  supported via `NANOPHP_BASIC_AUTH_USERNAME`/`NANOPHP_BASIC_AUTH_PASSWORD`,
  mirroring atto's `ATTO_BASIC_AUTH_*`. The `node` subcommand (a NanoPHP
  addition beyond atto) probes a built-in list of public RPC nodes, reports
  which respond, and saves the first working one to `~/.nanophp-node` for
  later commands; probing happens only when that command is run explicitly.
- `AGENT.md` — agent/contributor guide following the AGENT.md standard;
  `CLAUDE.md` is now a pointer to it.
- `Dockerfile` + `.github/workflows/docker.yml` — prebuilt
  `ghcr.io/gigaionllc/nanophp` images (amd64/arm64); the verification
  suites run during the image build. See [DOCKER.md](DOCKER.md).
- `autoload.php` — standalone PSR-4 autoloader; Composer no longer needed.
- `NanoTool::hex2dec`/`dec2hex` — exact 128-bit hex↔decimal conversion.
- `test/native/verify.php` — 43-check offline suite: RFC 7693 vectors, the
  official Nano zero-seed derivation vector, and real mainnet blocks
  (genesis open block hash + signature + work, a state send block, an epoch
  v2 block) captured from the live network.
- `test/native/wallet.php` + mock nodes — 22-check NanoWallet integration
  test, including detection of a node that lies about account state.

## Fork / rebranding

- PHP namespace: `MikeRow\NanoPHP` → `GigaionLLC\NanoPHP`.
- Composer package: `mikerow/nanophp` → `gigaionllc/nanophp`; homepage and
  support URLs point at https://github.com/GigaionLLC/NanoPHP.
- Git remotes: `origin` → GigaionLLC/NanoPHP, `upstream` → MikeRow/NanoPHP.
- LICENSE retains MikeRow's copyright and adds Gigaion, LLC for the fork.
