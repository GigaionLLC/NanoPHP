# NanoPHP

[![CI](https://github.com/GigaionLLC/NanoPHP/actions/workflows/ci.yml/badge.svg)](https://github.com/GigaionLLC/NanoPHP/actions/workflows/ci.yml)

Self-contained PHP library and command line wallet for the
[Nano](https://nano.org) currency. No Composer, no extensions beyond bcmath,
no third-party code — all cryptography (BLAKE2b, Nano's Ed25519-BLAKE2b),
HTTP, and WebSocket handling is implemented in pure PHP inside this
repository, so it stays maintainable long term without relying on external
parties.

This is the **[GigaionLLC fork](https://github.com/GigaionLLC/NanoPHP)** of the
archived [MikeRow/NanoPHP](https://github.com/MikeRow/NanoPHP). It is a **heavy
rewrite** rather than a light patch: the cryptography, wallet, RPC/WebSocket
transports, tests, and documentation have been substantially rewritten and
modernized for PHP 8.1–8.5, and extended with the wallet capabilities of the
[atto](https://github.com/codesoap/atto) Go client.

> **⚠️ Test before you trust it.** Because this is a heavy rewrite — and because
> it moves real money — you are strongly encouraged to run the bundled test
> suites and validate the library against your own setup before using it in any
> kind of production environment. Start on a throwaway seed with small amounts.
> See [Verify the installation](#verify-the-installation).

> **AI-enhanced project.** NanoPHP is developed, modernized, and maintained
> with extensive use of AI coding agents. The cryptography rewrite, the native
> wallet, the test suites, and the documentation were all produced and verified
> with AI assistance. Agent and contributor guidance follows the
> [AGENT.md](AGENT.md) standard.

---

## Security model

Same guarantees as atto:

- **Signatures are created locally, without the help of a node.** Seeds and
  private keys never leave your machine, so they cannot be stolen by a node
  operator.
- **Account info received from a node is validated using block signatures.**
  The frontier block is re-hashed and signature-verified locally, so a node
  operator cannot manipulate the wallet by, for example, reporting wrong
  balances.

---

## Requirements

- 64-bit PHP 8.1+ (tested up to 8.5) with the `bcmath` extension
- optional: `openssl` extension, only for RPC over https / WebSocket over wss

---

## Install

Traditional — clone (or download) and require one file, no package manager:

```sh
git clone https://github.com/GigaionLLC/NanoPHP.git
```

```php
require '/path/to/NanoPHP/autoload.php';

use GigaionLLC\NanoPHP\NanoTool;

[$private, $public, $account] = NanoTool::keys(true);
```

Composer also works, but is never required:

```sh
composer require gigaionllc/nanophp
```

Or skip installing PHP entirely with the prebuilt Docker image — PHP 8.5,
bcmath, library and CLI included, with the full verification suite run at
image build time:

```sh
docker run --rm ghcr.io/gigaionllc/nanophp new > seed.txt
docker run --rm -i ghcr.io/gigaionllc/nanophp address < seed.txt
```

See [docs/DOCKER.md](docs/DOCKER.md) for compose usage, vendoring the
library into your own images with `COPY --from`, and a complete
nginx + PHP-FPM example.

---

## Command line wallet

`nanophp` in the repo root is a CLI wallet modeled after atto:

```
$ php nanophp -h
Usage:
	php nanophp -v
	php nanophp n[ew]
	php nanophp no[de]
	php nanophp [-a ACCOUNT_INDEX] a[ddress]
	php nanophp [-a ACCOUNT_INDEX] b[alance]
	php nanophp [-a ACCOUNT_INDEX] rec[eive]
	php nanophp [-a ACCOUNT_INDEX] r[epresentative] [NEW_REPRESENTATIVE]
	php nanophp [-a ACCOUNT_INDEX] [-y] s[end] AMOUNT RECEIVER
```

Subcommands can be abbreviated to the bracketed prefixes, like atto. Every
subcommand except `new` and `node` reads the seed from the first line of
standard input, so seeds stay out of your shell history:

```
$ php nanophp new
1A914DF1FB3F3E3490AF1A4AF883C108D26EF9D56E524C2305E0E3C8BF74F1FB

$ php nanophp new | tee seed.txt | php nanophp address
nano_1xdgykk5rtoyxpgyhimnu15ib3uq5wr53yuj1eftwdjougyyyph9csct3hn6

$ php nanophp balance < seed.txt
Received 2 NANO in block 4A2A8E70527A1E35D74B079B1963FEDF626C1701CFB7BCDBD6761F2AACF69DBC
7 NANO

$ php nanophp representative < seed.txt
nano_11pb5aa6uirs9hoqsg4swnzyehoiqowj94kdpthwkhwufmtd6a11xx35iron

$ # Choosing a representative is important for keeping the network
$ # decentralized.
$ php nanophp representative nano_11pb5aa6uirs9hoqsg4swnzyehoiqowj94kdpthwkhwufmtd6a11xx35iron < seed.txt
Changed representative in block 6B037402CD4FF1715D6EC1DAFFD62FC2943621B63EC3AFEB006D3BDCAABC9899

$ php nanophp send 0.1 nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3 < seed.txt
Send 0.1 NANO to nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3? [y/N]: y
420EAC977E45A536153AC0865C2FDF51A2609E3B3946F1D7A976C3C06CEDE0E0

$ php nanophp -a 5 address < seed.txt
nano_3mkgs5khhaw36gdik1wj57q4nctaajfttmw1ngr4smn49m39fz5ux7ofsrya
```

`balance` automatically receives any receivable blocks first (use `receive`
to only do that part). `-a` selects the account index, `-y` skips the send
confirmation, `representative NEW_REP` changes the representative.

### PowerShell

PowerShell has no `<` input-redirection operator, so pipe the seed in with
`Get-Content` instead. Everything else is identical:

```powershell
PS> php nanophp new > seed.txt

PS> Get-Content seed.txt | php nanophp address
nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7

PS> Get-Content seed.txt | php nanophp balance
Received 2 NANO in block 4A2A8E70527A1E35D74B079B1963FEDF626C1701CFB7BCDBD6761F2AACF69DBC
7 NANO

PS> Get-Content seed.txt | php nanophp representative
nano_11pb5aa6uirs9hoqsg4swnzyehoiqowj94kdpthwkhwufmtd6a11xx35iron

PS> # Choosing a representative is important for keeping the network decentralized.
PS> Get-Content seed.txt | php nanophp representative nano_11pb5aa6uirs9hoqsg4swnzyehoiqowj94kdpthwkhwufmtd6a11xx35iron
Changed representative in block 6B037402CD4FF1715D6EC1DAFFD62FC2943621B63EC3AFEB006D3BDCAABC9899

PS> Get-Content seed.txt | php nanophp send 0.1 nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3
Send 0.1 NANO to nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3? [y/N]: y
9A6A21C6C672FEEDE191144CE83C099DD7BDDB74DBE42E285B905EDCFFEE9EE4

PS> Get-Content seed.txt | php nanophp -a 5 address
nano_3mkgs5khhaw36gdik1wj57q4nctaajfttmw1ngr4smn49m39fz5ux7ofsrya
```

The seed parser tolerates the BOMs and UTF-16 encoding that Windows
PowerShell's `>` and `Out-File` produce by default, so plain redirection
works too.

### Choosing a node

Without configuration the CLI talks to a local node at
`http://localhost:7076`. If you don't run your own node, `php nanophp node`
probes a built-in list of public RPC nodes, reports which respond, and saves
the first working one. Probing only happens when you run this command
explicitly — no other command ever probes or switches nodes on its own:

```
$ php nanophp node
Probing public Nano RPC nodes (preferred order)...

  [1/4] https://rainstorm.city/api         ... online (block height 220078141)

Selected node: https://rainstorm.city/api
Saved to /home/you/.nanophp-node — nanophp will use it automatically from now on.

To also export it into your current shell session:
  PowerShell:  $env:NANOPHP_NODE = "https://rainstorm.city/api"
  bash/zsh:    export NANOPHP_NODE=https://rainstorm.city/api
```

If a node is unreachable it prints `no (reason)` and moves to the next one.
Later commands simply read the saved choice from `~/.nanophp-node` — they
never probe. Node selection precedence is: the `NANOPHP_NODE` environment
variable, then the saved node, then localhost. So you can always override
per-shell:

```sh
export NANOPHP_NODE=http://my-node:7076      # POSIX shells
```

```powershell
PS> $env:NANOPHP_NODE = "http://my-node:7076"
```

The bundled public nodes use https, which requires the openssl extension; if
it isn't enabled, `nanophp node` will say so for each one.

If your node sits behind HTTP Basic Authentication, set the credentials the
same way atto does (`ATTO_BASIC_AUTH_*`), and every request will carry them:

```sh
export NANOPHP_BASIC_AUTH_USERNAME=rpcuser   # POSIX shells
export NANOPHP_BASIC_AUTH_PASSWORD=s3cret
```

```powershell
PS> $env:NANOPHP_BASIC_AUTH_USERNAME = "rpcuser"
PS> $env:NANOPHP_BASIC_AUTH_PASSWORD = "s3cret"
```

In library code, pass the header through `NanoRPC` options instead:

```php
$rpc = new NanoRPC('https', 'my-node', 443, null, [
    'headers' => ['Authorization: Basic ' . base64_encode('rpcuser:s3cret')]
]);
```

---

## Library examples

Each of these runs directly in a terminal from the repo root. They are
written for POSIX shells; on PowerShell, wrap the code in single quotes and
escape the inner double quotes as `\"`:

```powershell
PS> php -r 'require \"autoload.php\"; echo GigaionLLC\NanoPHP\NanoTool::den2raw(\"1.337\", \"NANO\"), PHP_EOL;'
1337000000000000000000000000000
```

Derive keys and the address from a seed:

```
$ php -r "require 'autoload.php';
    print_r(GigaionLLC\NanoPHP\NanoTool::seed2keys('1A914DF1FB3F3E3490AF1A4AF883C108D26EF9D56E524C2305E0E3C8BF74F1FB', 0, true));"
Array
(
    [0] => 03D46CA28387224FFDC7E33A6DC2DBCA84EBEFAC40393DFF31AED5FE9B13887C
    [1] => 756EF4A43C6ABEED9DE7C274D8070487771F3030FB71031BAE2E35DBBDEF59E7
    [2] => nano_1xdgykk5rtoyxpgyhimnu15ib3uq5wr53yuj1eftwdjougyyyph9csct3hn6
)
```

Convert between an address and its public key (the checksum is verified):

```
$ php -r "require 'autoload.php';
    echo GigaionLLC\NanoPHP\NanoTool::account2public('nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7'), PHP_EOL;"
C008B814A7D269A1FA3C6528B19201A24D797912DB9996FF02A1FF356E45552B
```

Convert amounts between NANO and raw without precision loss:

```
$ php -r "require 'autoload.php'; echo GigaionLLC\NanoPHP\NanoTool::den2raw('1.337', 'NANO'), PHP_EOL;"
1337000000000000000000000000000

$ php -r "require 'autoload.php'; echo GigaionLLC\NanoPHP\NanoTool::raw2den('1337000000000000000000000000000', 'NANO'), PHP_EOL;"
1.337
```

Sign a block hash and validate proof of work (genesis block shown):

```
$ php -r "require 'autoload.php';
    echo GigaionLLC\NanoPHP\NanoTool::sign(
        '991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948',
        '9F0E444C69F77A49BD0BE89DB92C38FE713E0963165CCA12FAF5712D7657120F'
    ), PHP_EOL;"
715DEDC047B30C016EA3B42CAB81E4F3D97996332154C53A33A2CB6E8AE19B692B7F348C47868EBDEF2565BFE783B593C2FA07EEE1022E966CDFDD587C059507

$ php -r "require 'autoload.php';
    echo GigaionLLC\NanoPHP\NanoTool::validWork(
        'E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA',
        'ffffffc000000000', '62f05417dd3fb691'
    ) ? 'valid' : 'invalid', PHP_EOL;"
valid
```

BIP39 mnemonics (wordlist is bundled; checksums are verified):

```
$ php -r "require 'autoload.php';
    echo implode(' ', GigaionLLC\NanoPHP\NanoTool::hex2mnem('1A914DF1FB3F3E3490AF1A4AF883C108D26EF9D56E524C2305E0E3C8BF74F1FB')), PHP_EOL;"
box media ladder wait view bottom dress today enough series utility balance cheap language fiber ski equip blouse join shy message risk side grocery
```

The high-level wallet, in a script:

```php
require '/path/to/NanoPHP/autoload.php';

use GigaionLLC\NanoPHP\NanoRPC;
use GigaionLLC\NanoPHP\NanoWallet;

$rpc    = new NanoRPC('http', 'localhost', 7076);
$wallet = NanoWallet::fromSeed($rpc, $seed, 0);

echo $wallet->address(), "\n";
$wallet->receiveAll();                        // pull in receivables, opens the account if new
echo $wallet->balance(), "\n";                // raw
$hash = $wallet->send('0.05', $destination);  // amount in NANO, signed locally
$wallet->changeRepresentative('nano_11pb5aa6uirs9hoqsg4swnzyehoiqowj94kdpthwkhwufmtd6a11xx35iron');
```

Building and signing a block manually (offline) and publishing it yourself:

```php
use GigaionLLC\NanoPHP\{NanoTool, NanoBlock, NanoRPC};

$rpc  = new NanoRPC('http', 'localhost', 7076);
$info = $rpc->account_info(['account' => $account, 'representative' => 'true']);

$block = new NanoBlock($private_key);
$block->setPrev($info['frontier'], [
    'type' => 'state', 'account' => $account, 'previous' => '',
    'representative' => $info['representative'], 'balance' => $info['balance'],
    'link' => '', 'signature' => '', 'work' => ''
]);
$block->setWork($rpc->work_generate(['hash' => $info['frontier']])['work']);

$send = $block->send($destination_account, $raw_amount);   // signed locally
$hash = $rpc->process(['json_block' => 'true', 'subtype' => 'send', 'block' => $send]);
```

More runnable examples for every `NanoTool` function are in
[test/NanoTool/](test/NanoTool).

---

## Verify the installation

The test suites run offline and check the cryptography against RFC 7693
vectors, the official Nano key-derivation vector and real mainnet blocks:

```sh
php test/native/verify.php      # crypto, tools, blocks   (43 checks)
php test/native/wallet.php      # NanoWallet vs mock node (22 checks)
php test/native/websocket.php   # bundled WebSocket client (7 checks)
```

---

## Features

| Class | Purpose |
|---|---|
| [NanoWallet](src/NanoWallet.php) | atto-style account workflows: receive, send, representatives, verified account info |
| [NanoTool](src/NanoTool.php) | node-independent functions: keys, addresses, signing, work, units, BIP39/44 |
| [NanoBlock](src/NanoBlock.php) | building and locally signing state blocks |
| [NanoRPC](src/NanoRPC.php) | node RPC over native PHP streams |
| [NanoRPCExt](src/NanoRPCExt.php) | multi-account RPC conveniences (sweep, send, weight) |
| [NanoWS](src/NanoWS.php) | node WebSocket subscriptions (bundled RFC 6455 client) |
| [NanoCLI](src/NanoCLI.php) | wrapper for the nano_node CLI binary |
| [NanoIPC](src/NanoIPC.php) | node IPC transport |
| [Crypto\Blake2b](src/Crypto/Blake2b.php) | pure PHP BLAKE2b (RFC 7693) |
| [Crypto\Ed25519Blake2b](src/Crypto/Ed25519Blake2b.php) | pure PHP Ed25519-BLAKE2b, the Nano network variant |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the classes interconnect
- [docs/MODERNIZATION.md](docs/MODERNIZATION.md) — all changes and fixes since the archived upstream
- [docs/CRYPTO.md](docs/CRYPTO.md) — the crypto implementations and their verification
- [docs/WALLET.md](docs/WALLET.md) — NanoWallet guide and the atto feature mapping
- [docs/DOCKER.md](docs/DOCKER.md) — prebuilt images: docker run, compose, and nginx/PHP-FPM integration
- [AGENT.md](AGENT.md) — contributor / AI-agent guide and project constraints (the [AGENT.md](https://agent.md) standard; [CLAUDE.md](CLAUDE.md) points here)

---

## FAQ

#### How to perform calculations with Nano denominations or raws?

<details><summary>PHP faces troubles when dealing with Nano amounts ...</summary>
<p>

- Data type `float` isn't precise at certain decimal depths
- Data type `integer` size is limited to 64 bit

Perform calculations in raws using
[bcmath](https://www.php.net/manual/en/book.bc.php) string math, as NanoPHP
does internally. `NanoTool::hex2dec()` and `NanoTool::dec2hex()` convert
128-bit balances between formats without precision loss.

</p>
</details>

#### Why not use libsodium for signatures?

<details><summary>Nano is not compatible with standard Ed25519 ...</summary>
<p>

- Nano's Ed25519 variant uses BLAKE2b-512 as the internal hash, while
  `sodium_crypto_sign_*` uses SHA-512
- PHP builds without the sodium extension have no BLAKE2b at all

NanoPHP therefore ships its own pure PHP BLAKE2b and Ed25519-BLAKE2b
implementations with no extension dependencies beyond `bcmath`. See
[docs/CRYPTO.md](docs/CRYPTO.md).

</p>
</details>

#### Should I generate proof of work in PHP?

<details><summary>Only at low difficulties ...</summary>
<p>

`NanoTool::work()` is fully functional but pure PHP hashing is slow; at the
mainnet send threshold (`fffffff800000000`) it can take hours. Prefer
`work_generate` against a node or a dedicated work server (NanoWallet's
default), and use `NanoTool::validWork()` to validate results locally.

</p>
</details>

---

## Credits

This fork builds on the work and effort of

- [MikeRow/NanoPHP](https://github.com/MikeRow/NanoPHP) — the original library
- [codesoap/atto](https://github.com/codesoap/atto) — the wallet workflow and security model NanoWallet is modeled after
- [aceat64/EasyBitcoin-PHP](https://github.com/aceat64/EasyBitcoin-PHP)
- [jaimehgb/RaiBlocksPHP](https://github.com/jaimehgb/RaiBlocksPHP)
- [Sergey Kroshnin](https://github.com/SergiySW)
