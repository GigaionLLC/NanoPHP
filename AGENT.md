# AGENT.md

Canonical guidance for AI coding agents (and humans) working in this
repository, following the [AGENT.md](https://agent.md) convention. This file
is the single source of truth; `CLAUDE.md` and any other agent-specific files
simply point here.

NanoPHP is developed and enhanced with extensive use of AI coding agents, so
keeping this guide accurate is part of the work: update it in the same change
whenever you alter constraints, commands, or architecture.

## What this is

NanoPHP is a dependency-free PHP library for the Nano cryptocurrency: key
derivation, account/address encoding, block building and signing, proof-of-work
validation, node RPC, and a high-level wallet (`NanoWallet`) with feature parity
to the [atto](https://github.com/codesoap/atto) Go client. The repo root also
ships `nanophp`, an atto-style command line wallet.

This is the **GigaionLLC fork** (https://github.com/GigaionLLC/NanoPHP) of the
archived MikeRow/NanoPHP. Git remotes: `origin` → GigaionLLC/NanoPHP (push
here), `upstream` → MikeRow/NanoPHP (archived, reference only).

## Hard constraints — read before changing dependencies

The minimum supported runtime is a **bare PHP build**: 64-bit PHP 8.1+ with
**only `bcmath`** beyond the always-on extensions — no curl, gmp, sodium,
openssl, mbstring, sockets, or blake2 in `hash_algos()`, and **no Composer**.
The library must keep working on that floor (a given dev machine may have more
enabled, e.g. openssl for https; never make the library *require* it).
Everything in `src/` (except `NanoWS`/`NanoIPC`, see below) abides by:

- Big integers → `bcmath` (never gmp, never float for raw amounts)
- Hashing → `src/Crypto/Blake2b.php` (pure PHP; PHP's `hash()` has no blake2b)
- Signatures → `src/Crypto/Ed25519Blake2b.php` (Nano uses Ed25519 with
  BLAKE2b-512, which libsodium cannot do)
- HTTP → PHP streams (`file_get_contents` + context), never curl functions
- HTTPS/wss → used only when openssl is present; `NanoRPC`/`NanoWS` throw a
  clear error otherwise, never a hard dependency
- WebSockets → `src/Util/WebSocketClient.php` (bundled RFC 6455 client),
  never a websocket package
- Loading → `autoload.php` at the repo root (standalone PSR-4); Composer is
  optional, never required

**Self-containment is a project goal**: no third-party code at runtime, so the
library stays maintainable without relying on external parties. The single
exception is `NanoIPC`'s legacy FlatBuffers preprocessing path (optional,
modern nodes use JSON); don't add new external dependencies.

Two security properties (inherited from atto) must be preserved by any change:
**signatures are always created locally** — the seed/private key is never sent
to a node — and **account info received from a node is validated against the
frontier block's recomputed hash and signature** (`NanoWallet` `verify_info`,
on by default), so a node operator can't report wrong balances.

## Commands

```sh
php test/native/verify.php      # offline crypto/tool suite (RFC + mainnet vectors)
php test/native/wallet.php      # NanoWallet integration test (spawns mock node)
php test/native/websocket.php   # bundled WebSocket client (spawns echo server)
php -l src/<file>.php           # lint
```

All three test scripts exit non-zero on failure and must pass before pushing.
There is no PHPUnit; tests are plain scripts using the `check()` helper.
`test/NanoTool/*.php` are runnable usage examples, not assertions.

CI (`.github/workflows/ci.yml`) runs the lint, all three suites, and a CLI
smoke test on every push to master and every pull request, across PHP 8.1
(the version floor), 8.4, and 8.5 with only the bcmath extension installed —
which doubles as proof of the zero-dependency claim. A separate job runs
PHPStan (level 5, config `phpstan.neon`, pinned PHAR — no Composer) over the
maintained core classes. Keep the workflow's suite list in sync when adding
test scripts. `php -l` and PHPStan only catch syntax and type-level issues;
**logic bugs (currency precision, input validation, allocation limits) are
guarded by behavioral assertions in `test/native/verify.php` — add a
regression check there for every such bug fixed.**

Docker: the `Dockerfile` builds `ghcr.io/gigaionllc/nanophp` (php:8.5-cli-alpine
+ bcmath, unprivileged user, entrypoint = the CLI) and runs the lint and all
three suites during the build — a build failure means broken code, by design.
`.github/workflows/docker.yml` publishes amd64+arm64 images on master pushes
(`:latest`) and `v*` tags (semver pins). Usage docs: docs/DOCKER.md.
Keep the Dockerfile's verification step in sync with the suite list too.

## Architecture in one paragraph

`Crypto\Blake2b` and `Crypto\Ed25519Blake2b` are the foundation. `NanoTool`
(all-static) wraps them into Nano semantics: seeds→keys, key↔address (base32 +
5-byte checksum), state-block hashing (`hashHexs`), sign/verify, work, unit
conversion, BIP39/44. `NanoBlock` builds and signs state blocks (open / receive
/ send / change) using `NanoTool`. `NanoRPC` is a thin JSON-over-HTTP client
(magic `__call` maps method name → RPC action). `NanoWallet` orchestrates all
of the above into atto-style workflows and verifies `account_info` responses
against the frontier block's recomputed hash and signature. The `nanophp` CLI
is a thin front-end over `NanoWallet`. Details in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Conventions and gotchas

- Namespace is `GigaionLLC\NanoPHP\` (PSR-4 from `src/`). Tests load via
  `test/autoload.php`, which falls back to the bundled root `autoload.php`.
- Hex strings are UPPERCASE except work/difficulty values, which the Nano
  RPC convention keeps lowercase.
- Raw balances are always **decimal strings** (128-bit values overflow PHP
  ints/floats — this caused real bugs in the original library; see
  [docs/MODERNIZATION.md](docs/MODERNIZATION.md)).
- Nano state-block hash = BLAKE2b-256 over: preamble(0x...06, 32 bytes) ‖
  account pubkey ‖ previous ‖ representative pubkey ‖ balance (16-byte BE) ‖
  link. Work value = BLAKE2b-8(nonce LE ‖ hash) read little-endian, valid when
  ≥ difficulty. Receive/open blocks use the lower threshold
  `fffffe0000000000`; send/change use `fffffff800000000`.
- Epoch blocks are signed by the network's epoch signer, NOT the account —
  any signature verification of arbitrary frontiers must special-case links
  starting with ASCII "epoch" (hex `65706F6368`).
- The crypto is intentionally not constant-time (server-side use); don't
  advertise it for hostile-input timing scenarios.
- Pure-PHP work generation (`NanoTool::work`) is only practical at low
  difficulties; real work comes from a node/work server via
  `work_generate`.
- When tests need real network data, fetch it once (PHP streams over HTTPS
  if openssl is enabled, otherwise the curl CLI), then bake the results into
  the offline tests as static vectors — tests must stay deterministic and
  network-free. See the mainnet vectors in `test/native/verify.php`.

## Docs index

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — classes and how they interconnect
- [docs/MODERNIZATION.md](docs/MODERNIZATION.md) — every change/fix made since the archived upstream
- [docs/CRYPTO.md](docs/CRYPTO.md) — the BLAKE2b / Ed25519-BLAKE2b implementations and their verification
- [docs/WALLET.md](docs/WALLET.md) — NanoWallet usage and the atto feature mapping
