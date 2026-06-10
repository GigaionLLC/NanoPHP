<?php

namespace GigaionLLC\NanoPHP\Crypto;

use \Exception;

class Blake2bException extends Exception{}

/**
 * Pure PHP implementation of BLAKE2b (RFC 7693).
 *
 * Requires 64-bit PHP. Each 64-bit word is stored as two 32-bit halves
 * so that additions never overflow PHP's signed 64-bit integers.
 *
 * Usage:
 *   $hash = Blake2b::hash($data, 32);            // one-shot, raw binary out
 *   $b2b  = new Blake2b(32);                     // incremental
 *   $b2b->update($chunk1)->update($chunk2);
 *   $hash = $b2b->digest();
 */
class Blake2b
{
    private const IV = [
        0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
        0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
        0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
        0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
    ];

    private const SIGMA = [
        [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
        [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3],
        [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4],
        [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8],
        [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13],
        [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9],
        [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11],
        [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10],
        [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5],
        [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0],
    ];

    /** @var int[] state: 8 words as [hi,lo] pairs (16 ints) */
    private array $h;

    /** @var int[] byte counter as 64-bit [hi,lo] (messages > 2^64 bytes unsupported) */
    private array $t = [0, 0];

    private string $buffer = '';
    private int $outLen;
    private bool $finalized = false;

    public function __construct(int $outLen = 64, string $key = '')
    {
        if (PHP_INT_SIZE < 8) {
            throw new Blake2bException('Blake2b requires 64-bit PHP');
        }
        if ($outLen < 1 || $outLen > 64) {
            throw new Blake2bException("Invalid output length: $outLen");
        }
        $keyLen = strlen($key);
        if ($keyLen > 64) {
            throw new Blake2bException("Invalid key length: $keyLen");
        }

        $this->outLen = $outLen;
        $this->h = self::IV;
        // Parameter block: digest_length | (key_length << 8) | (fanout=1 << 16) | (depth=1 << 24)
        $this->h[1] ^= $outLen ^ ($keyLen << 8) ^ 0x01010000;

        if ($keyLen > 0) {
            $this->update(str_pad($key, 128, "\x00"));
        }
    }

    public function update(string $data): static
    {
        if ($this->finalized) {
            throw new Blake2bException('Cannot update a finalized hash');
        }

        $this->buffer .= $data;

        // Keep at least one byte buffered: the last block must be
        // compressed with the finalization flag set in digest().
        while (strlen($this->buffer) > 128) {
            $this->incrementCounter(128);
            $this->compress(substr($this->buffer, 0, 128), false);
            $this->buffer = substr($this->buffer, 128);
        }

        return $this;
    }

    public function digest(): string
    {
        if ($this->finalized) {
            throw new Blake2bException('Hash is already finalized');
        }
        $this->finalized = true;

        $this->incrementCounter(strlen($this->buffer));
        $this->compress(str_pad($this->buffer, 128, "\x00"), true);
        $this->buffer = '';

        $words = [];
        for ($i = 0; $i < 16; $i += 2) {
            $words[] = $this->h[$i + 1]; // lo
            $words[] = $this->h[$i];     // hi
        }

        return substr(pack('V16', ...$words), 0, $this->outLen);
    }

    public static function hash(string $data, int $outLen = 64, string $key = ''): string
    {
        return (new self($outLen, $key))->update($data)->digest();
    }

    public static function hashHex(string $data, int $outLen = 64, string $key = ''): string
    {
        return strtoupper(bin2hex(self::hash($data, $outLen, $key)));
    }

    private function incrementCounter(int $bytes): void
    {
        $lo = $this->t[1] + $bytes;
        $this->t[0] = ($this->t[0] + ($lo >> 32)) & 0xffffffff;
        $this->t[1] = $lo & 0xffffffff;
    }

    private function compress(string $block, bool $final): void
    {
        // Message words, little-endian: m[2i] = hi half, m[2i+1] = lo half
        $u = unpack('V32', $block);
        $m = [];
        for ($i = 0; $i < 16; $i++) {
            $m[2 * $i]     = $u[2 * $i + 2];
            $m[2 * $i + 1] = $u[2 * $i + 1];
        }

        $v = array_merge($this->h, self::IV);
        $v[25] ^= $this->t[1]; // v12 lo ^= t0 lo
        $v[24] ^= $this->t[0]; // v12 hi ^= t0 hi
        // v13 ^= t1 (always 0 here)

        if ($final) {
            $v[28] ^= 0xffffffff;
            $v[29] ^= 0xffffffff;
        }

        for ($r = 0; $r < 12; $r++) {
            $s = self::SIGMA[$r % 10];
            $this->g($v, $m, 0, 4,  8, 12, $s[0],  $s[1]);
            $this->g($v, $m, 1, 5,  9, 13, $s[2],  $s[3]);
            $this->g($v, $m, 2, 6, 10, 14, $s[4],  $s[5]);
            $this->g($v, $m, 3, 7, 11, 15, $s[6],  $s[7]);
            $this->g($v, $m, 0, 5, 10, 15, $s[8],  $s[9]);
            $this->g($v, $m, 1, 6, 11, 12, $s[10], $s[11]);
            $this->g($v, $m, 2, 7,  8, 13, $s[12], $s[13]);
            $this->g($v, $m, 3, 4,  9, 14, $s[14], $s[15]);
        }

        for ($i = 0; $i < 16; $i++) {
            $this->h[$i] ^= $v[$i] ^ $v[$i + 16];
        }
    }

    /**
     * BLAKE2b mixing function G operating on [hi,lo] word pairs.
     * $a,$b,$c,$d are word indexes; $x,$y are message word indexes.
     */
    private function g(array &$v, array $m, int $a, int $b, int $c, int $d, int $x, int $y): void
    {
        $a2 = $a * 2; $b2 = $b * 2; $c2 = $c * 2; $d2 = $d * 2;

        // a = a + b + m[x]
        $lo = $v[$a2 + 1] + $v[$b2 + 1] + $m[2 * $x + 1];
        $hi = $v[$a2] + $v[$b2] + $m[2 * $x] + ($lo >> 32);
        $v[$a2] = $hi & 0xffffffff; $v[$a2 + 1] = $lo & 0xffffffff;

        // d = rotr64(d ^ a, 32)  -> swap halves
        $hi = $v[$d2] ^ $v[$a2]; $lo = $v[$d2 + 1] ^ $v[$a2 + 1];
        $v[$d2] = $lo; $v[$d2 + 1] = $hi;

        // c = c + d
        $lo = $v[$c2 + 1] + $v[$d2 + 1];
        $hi = $v[$c2] + $v[$d2] + ($lo >> 32);
        $v[$c2] = $hi & 0xffffffff; $v[$c2 + 1] = $lo & 0xffffffff;

        // b = rotr64(b ^ c, 24)
        $hi = $v[$b2] ^ $v[$c2]; $lo = $v[$b2 + 1] ^ $v[$c2 + 1];
        $v[$b2]     = (($hi >> 24) | ($lo << 8)) & 0xffffffff;
        $v[$b2 + 1] = (($lo >> 24) | ($hi << 8)) & 0xffffffff;

        // a = a + b + m[y]
        $lo = $v[$a2 + 1] + $v[$b2 + 1] + $m[2 * $y + 1];
        $hi = $v[$a2] + $v[$b2] + $m[2 * $y] + ($lo >> 32);
        $v[$a2] = $hi & 0xffffffff; $v[$a2 + 1] = $lo & 0xffffffff;

        // d = rotr64(d ^ a, 16)
        $hi = $v[$d2] ^ $v[$a2]; $lo = $v[$d2 + 1] ^ $v[$a2 + 1];
        $v[$d2]     = (($hi >> 16) | ($lo << 16)) & 0xffffffff;
        $v[$d2 + 1] = (($lo >> 16) | ($hi << 16)) & 0xffffffff;

        // c = c + d
        $lo = $v[$c2 + 1] + $v[$d2 + 1];
        $hi = $v[$c2] + $v[$d2] + ($lo >> 32);
        $v[$c2] = $hi & 0xffffffff; $v[$c2 + 1] = $lo & 0xffffffff;

        // b = rotr64(b ^ c, 63)  -> rotl 1
        $hi = $v[$b2] ^ $v[$c2]; $lo = $v[$b2 + 1] ^ $v[$c2 + 1];
        $v[$b2]     = (($hi << 1) | ($lo >> 31)) & 0xffffffff;
        $v[$b2 + 1] = (($lo << 1) | ($hi >> 31)) & 0xffffffff;
    }
}
