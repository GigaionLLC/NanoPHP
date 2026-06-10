# NanoPHP — self-contained PHP library and CLI wallet for Nano currency.
#
# The build runs the full offline verification suite (crypto vectors,
# wallet-vs-mock-node, WebSocket client), so an image that builds is an
# image whose cryptography is proven working.
#
#   docker build -t nanophp .
#   docker run --rm nanophp new
#
# See docs/DOCKER.md for usage, compose and nginx/PHP-FPM examples.

FROM php:8.5-cli-alpine

# bcmath is the library's only required extension; openssl (for https/wss
# to public nodes) is already built into the official image
RUN docker-php-ext-install bcmath

WORKDIR /app

COPY autoload.php composer.json LICENSE README.md nanophp ./
COPY src/ src/
COPY test/ test/

# Prove the image: lint everything, then run all three offline suites
RUN set -e; \
    for f in $(find src test -name '*.php') nanophp autoload.php; do php -l "$f" > /dev/null; done; \
    php test/native/verify.php; \
    php test/native/wallet.php; \
    php test/native/websocket.php

# Run as an unprivileged user; seeds piped via stdin never touch the layer fs
RUN adduser -D -u 1000 nanophp
USER nanophp

# Saved node selection (`nanophp node`) lands here; mount a volume over
# /home/nanophp to persist it, or just set NANOPHP_NODE instead
ENV HOME=/home/nanophp

LABEL org.opencontainers.image.title="NanoPHP" \
      org.opencontainers.image.description="Self-contained PHP library and CLI wallet for Nano currency. Zero dependencies beyond bcmath; local signing; node responses verified by block signature." \
      org.opencontainers.image.source="https://github.com/GigaionLLC/NanoPHP" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Gigaion, LLC"

ENTRYPOINT ["php", "/app/nanophp"]
CMD ["-h"]
