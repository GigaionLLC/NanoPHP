# Docker

Prebuilt images let you use NanoPHP without installing PHP at all. The image
contains PHP 8.5 (Alpine), the bcmath extension, the library, the `nanophp`
CLI wallet and the test suites — nothing else. **The full offline
verification suite runs during the image build**, so an image that exists is
an image whose cryptography passed every check.

Images are published to GitHub Container Registry by CI:

| Tag | Meaning |
|---|---|
| `ghcr.io/gigaionllc/nanophp:latest` | latest release |
| `ghcr.io/gigaionllc/nanophp:1`, `:1.0`, `:1.0.0` | semver pins |
| `ghcr.io/gigaionllc/nanophp:edge` | current master |
| `ghcr.io/gigaionllc/nanophp:sha-<commit>` | immutable, per commit |

Both `linux/amd64` and `linux/arm64` are published.

## CLI wallet with `docker run`

The image's entrypoint is the `nanophp` CLI, so subcommands map directly.
Use `-i` whenever a command reads the seed from standard input:

```sh
# Generate a seed (keep it safe!)
docker run --rm ghcr.io/gigaionllc/nanophp new > seed.txt

# Derive the address
docker run --rm -i ghcr.io/gigaionllc/nanophp address < seed.txt

# Point at a node and check the balance (receives receivables first)
docker run --rm -i -e NANOPHP_NODE=https://rainstorm.city/api \
    ghcr.io/gigaionllc/nanophp balance < seed.txt

# Send (the -y skips the interactive confirmation, which has no TTY here)
docker run --rm -i -e NANOPHP_NODE=https://rainstorm.city/api \
    ghcr.io/gigaionllc/nanophp -y send 0.1 nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3 < seed.txt

# Help / version
docker run --rm ghcr.io/gigaionllc/nanophp -h
docker run --rm ghcr.io/gigaionllc/nanophp -v
```

Environment variables work exactly like the bare CLI: `NANOPHP_NODE`,
`NANOPHP_BASIC_AUTH_USERNAME`, `NANOPHP_BASIC_AUTH_PASSWORD`. In containers,
prefer `-e NANOPHP_NODE=...` over `nanophp node` (the saved selection in
`~/.nanophp-node` disappears with the container unless you mount a volume
over `/home/nanophp`).

Note: the official PHP image includes openssl, so https public nodes work
out of the box — even if your host PHP can't do https.

## Verify the image yourself

Don't take the build's word for it:

```sh
docker run --rm --entrypoint php ghcr.io/gigaionllc/nanophp test/native/verify.php
```

## Ad-hoc PHP with the library loaded

```sh
docker run --rm --entrypoint php ghcr.io/gigaionllc/nanophp -r \
    'require "/app/autoload.php"; print_r(GigaionLLC\NanoPHP\NanoTool::keys(true));'
```

## docker compose

For interactive/recurring CLI use, define it once and `run` it:

```yaml
# compose.yaml
services:
  nanophp:
    image: ghcr.io/gigaionllc/nanophp:latest
    environment:
      NANOPHP_NODE: https://rainstorm.city/api
      # NANOPHP_BASIC_AUTH_USERNAME: rpcuser
      # NANOPHP_BASIC_AUTH_PASSWORD: s3cret
```

```sh
docker compose run --rm -T nanophp address < seed.txt
docker compose run --rm -T nanophp balance < seed.txt
```

(`-T` disables the TTY so stdin piping works.)

## As a dependency of your own application image

The image doubles as a distribution artifact: copy the library out of it in
your own Dockerfile (multi-stage `COPY --from`), pinning a version tag. This
is the standard pattern for vendoring a dependency without a package
manager:

```dockerfile
FROM php:8.5-fpm-alpine

RUN docker-php-ext-install bcmath

# Vendor NanoPHP from the prebuilt image
COPY --from=ghcr.io/gigaionllc/nanophp:1.0.0 /app /opt/nanophp

COPY public/ /var/www/html/
```

```php
<?php // your application code
require '/opt/nanophp/autoload.php';

use GigaionLLC\NanoPHP\NanoTool;
```

## Behind nginx (PHP-FPM)

A complete web-facing example — nginx serving a PHP app that uses NanoPHP.
Three files:

```dockerfile
# Dockerfile.app
FROM php:8.5-fpm-alpine
RUN docker-php-ext-install bcmath
COPY --from=ghcr.io/gigaionllc/nanophp:latest /app /opt/nanophp
COPY public/ /var/www/html/
```

```yaml
# compose.yaml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.app
    volumes:
      - ./public:/var/www/html:ro

  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    volumes:
      - ./public:/var/www/html:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - app
```

```nginx
# nginx.conf
server {
    listen 80;
    root /var/www/html;
    index index.php;

    location ~ \.php$ {
        fastcgi_pass app:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

```php
<?php // public/index.php — toy example: validate an address from the query
require '/opt/nanophp/autoload.php';

use GigaionLLC\NanoPHP\NanoTool;

header('Content-Type: application/json');

$account = $_GET['account'] ?? '';
$public  = NanoTool::account2public($account);

echo json_encode($public
    ? ['valid' => true,  'public_key' => $public]
    : ['valid' => false]
);
```

```sh
docker compose up -d
curl "http://localhost:8080/?account=nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
# {"valid":true,"public_key":"E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA"}
```

Security reminder: never put seeds or private keys in images, compose files
or environment variables of web-facing services. Signing belongs in backend
code that reads keys from a proper secret store; the wallet CLI reads seeds
from stdin for exactly this reason.

## Building locally

```sh
docker build -t nanophp .
docker run --rm nanophp -v
```

The build fails if any lint or verification check fails.

## Publishing (maintainers)

`.github/workflows/docker.yml` publishes on every push to master (`:edge`)
and on every `v*` tag (`:latest` + semver tags), for amd64 and arm64. The
GHCR package is created automatically on the first publish and linked to
the repository via the `org.opencontainers.image.source` label. After the
first publish, set the package visibility to **public** once under
github.com → GigaionLLC → Packages → nanophp → Package settings.
