# Cryptography

Why NanoPHP ships its own crypto, what exactly it implements, and how it is
verified. Both implementations live in `src/Crypto/` and require nothing
beyond 64-bit PHP with bcmath.

## Why custom implementations are unavoidable

Nano's signature scheme is **Ed25519 with BLAKE2b-512 as the internal hash**
instead of SHA-512. That single substitution makes every standard Ed25519
implementation incompatible:

- `sodium_crypto_sign_*` (libsodium) hard-codes SHA-512 — signatures and
  derived public keys simply don't match Nano's.
- PHP's `hash()` does not offer blake2b at all (check `hash_algos()`), so even
  the hash half can't come from the standard library.
- The bare PHP builds this library targets also lack the gmp and sodium
  extensions entirely.

The archived upstream solved this with the `mikerow/salt` Composer package and
an optional `ext-blake2` C extension. This fork replaces both with
self-contained code.

## Crypto\Blake2b

[src/Crypto/Blake2b.php](../src/Crypto/Blake2b.php) — BLAKE2b per RFC 7693.

- Output lengths 1–64 bytes, optional key (0–64 bytes), incremental
  (`update`/`digest`) and one-shot (`Blake2b::hash($data, $len)`) APIs.
- 64-bit words are stored as `[hi32, lo32]` pairs; all additions happen on
  32-bit halves with explicit carries, so nothing ever overflows PHP's signed
  64-bit integers (PHP silently converts overflow to float, which would
  corrupt the state).
- The final block is buffered until `digest()` so the finalization flag is set
  correctly; `update()` keeps at least one byte in the buffer at all times.

Where each output length is used in Nano:

| Length | Use |
|---|---|
| 64 | Ed25519-BLAKE2b internal hash (key expansion, `r`, `k`) |
| 32 | block hashes, seed → private key derivation |
| 8 | proof-of-work values |
| 5 | account address checksums |

## Crypto\Ed25519Blake2b

[src/Crypto/Ed25519Blake2b.php](../src/Crypto/Ed25519Blake2b.php) — RFC 8032
Ed25519 with BLAKE2b-512 substituted, on bcmath big integers.

- Curve: twisted Edwards `-x² + y² = 1 + d·x²y²` over GF(2²⁵⁵ − 19); points in
  extended homogeneous coordinates (X : Y : Z : T); the unified `add-2008-hwcd`
  addition and `dbl-2008-hwcd` doubling formulas.
- Scalar multiplication: plain double-and-add, MSB first.
- Inversion and square roots via `bcpowmod` (Fermat: `x^(p−2)`; sqrt:
  `x^((p+3)/8)` with the `sqrt(−1)` correction), so no hand-rolled extended
  GCD is needed.
- Key flow (the Nano/atto convention): `h = BLAKE2b-512(private_key)`;
  scalar `a = clamp(h[0..31])`; public key `A = a·B`. Signing uses
  `r = BLAKE2b-512(h[32..63] ‖ M) mod L`, `S = r + BLAKE2b-512(R‖A‖M)·a mod L`.
- Verification decodes A and R (rejecting out-of-range y and non-canonical
  `S ≥ L`) and checks `S·B = R + k·A` by comparing encodings.

Performance on this machine: ~8 ms public-key derivation, ~12 ms sign,
~15 ms verify — three orders of magnitude faster than needed for wallet use.

### Security notes

- **Not constant-time.** bcmath operation timing depends on operand values, so
  scalar bits leak through timing in principle. This matches the pure-PHP Salt
  library the upstream used and is acceptable for server-side wallets; do not
  use it where an attacker can take fine-grained timing measurements of
  signing with secrets they want to extract.
- Signing is deterministic (RFC 8032 style) — no RNG is consumed at sign time,
  so a bad RNG cannot leak the key through repeated nonces. Randomness is only
  used for `NanoTool::keys()` / `NanoWallet::newSeed()`, via `random_bytes()`.
- `hash_equals` is used for the signature-encoding and checksum comparisons.

## How it is all verified — `php test/native/verify.php`

The crypto is pinned against independent, externally produced values:

1. **RFC 7693 vectors** — BLAKE2b-512 of `""` and `"abc"`, BLAKE2b-256 of `""`,
   plus incremental-vs-one-shot equivalence over random data.
2. **Official Nano derivation vector** — zero seed, index 0 must produce
   private key `9F0E444C...`, public key `C008B814...`, and address
   `nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7`.
   This exercises BLAKE2b key derivation, clamping, scalar multiplication,
   point encoding, and the base32 address encoding end to end.
3. **Real mainnet blocks** (fetched once from a public RPC, then baked in as
   offline vectors):
   - the genesis open block: recomputed hash, the actual on-chain signature
     verifying against the genesis account, and its proof of work validating
     at the legacy threshold;
   - a state send block (`D2655449...`): recomputed state hash and on-chain
     signature;
   - an epoch v2 block: recomputed state hash (epoch blocks are signed by the
     epoch signer, so only the hash is asserted).
4. **Negative tests** — tampered signatures, wrong messages, bad address
   checksums, and below-threshold work must all be rejected.

If you touch anything in `src/Crypto/`, this suite must pass bit-for-bit.
