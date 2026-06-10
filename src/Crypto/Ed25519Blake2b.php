<?php

namespace GigaionLLC\NanoPHP\Crypto;

use \Exception;

class Ed25519Blake2bException extends Exception{}

/**
 * Ed25519 signatures using BLAKE2b-512 as the internal hash function,
 * as used by the Nano currency network.
 *
 * Standard Ed25519 (e.g. libsodium) uses SHA-512 internally and is NOT
 * compatible with Nano. This implementation follows RFC 8032 with the
 * hash swapped for BLAKE2b-512, built on bcmath big integers so it runs
 * on a bare PHP build (no gmp/sodium/openssl required).
 *
 * Note: this implementation is not constant-time. Like the pure-PHP
 * libraries it replaces, it is intended for server-side use where
 * timing side channels are not part of the threat model.
 */
class Ed25519Blake2b
{
    // Field prime p = 2^255 - 19
    private const P = '57896044618658097711785492504343953926634992332820282019728792003956564819949';

    // Group order L = 2^252 + 27742317777372353535851937790883648493
    private const L = '7237005577332262213973186563042994240857116359379907606001950938285454250989';

    // Twisted Edwards curve constant d = -121665/121666 mod p
    private const D = '37095705934669439343138083508754565189542113879843219016388785533085940283555';

    // 2*d mod p
    private const D2 = '16295367250680780974490674513165176452449235426866156013048779062215315747161';

    // sqrt(-1) mod p
    private const SQRT_M1 = '19681161376707505956807079304988542015446066515923890162744021073123829784752';

    // Base point B
    private const BX = '15112221349535400772501151409588531511454012693041857206046113283949847762202';
    private const BY = '46316835694926478169428394003475163141307993866256225615783033603165251855960';

    // (p + 3) / 8, used for square roots
    private const P38 = '7237005577332262213973186563042994240829374041602535252466099000494570602494';

    // p - 2, used for inversion via Fermat
    private const PM2 = '57896044618658097711785492504343953926634992332820282019728792003956564819947';


    // *
    // *  Public API (32/64-byte binary strings in, binary out)
    // *

    /**
     * Derive the public key from a 32-byte private key (Nano style:
     * the private key is hashed with BLAKE2b-512, then clamped).
     */
    public static function publicKey(string $privateKey): string
    {
        if (strlen($privateKey) != 32) {
            throw new Ed25519Blake2bException('Private key must be 32 bytes');
        }

        $h = Blake2b::hash($privateKey, 64);
        $a = self::clamp(substr($h, 0, 32));

        return self::encodePoint(self::scalarMultBase($a));
    }

    /**
     * Sign a message. Returns the 64-byte signature (R || S).
     */
    public static function sign(string $message, string $privateKey): string
    {
        if (strlen($privateKey) != 32) {
            throw new Ed25519Blake2bException('Private key must be 32 bytes');
        }

        $h = Blake2b::hash($privateKey, 64);
        $a = self::clamp(substr($h, 0, 32));
        $A = self::encodePoint(self::scalarMultBase($a));

        $r = bcmod(self::bytesToNum(Blake2b::hash(substr($h, 32, 32) . $message, 64)), self::L);
        $R = self::encodePoint(self::scalarMultBase($r));

        $k = bcmod(self::bytesToNum(Blake2b::hash($R . $A . $message, 64)), self::L);
        $S = bcmod(bcadd($r, bcmul($k, $a)), self::L);

        return $R . self::numToBytes($S, 32);
    }

    /**
     * Verify a 64-byte signature against a message and 32-byte public key.
     */
    public static function verify(string $message, string $signature, string $publicKey): bool
    {
        if (strlen($signature) != 64 || strlen($publicKey) != 32) {
            return false;
        }

        $A = self::decodePoint($publicKey);
        if ($A === null) {
            return false;
        }

        $Renc = substr($signature, 0, 32);
        $R = self::decodePoint($Renc);
        if ($R === null) {
            return false;
        }

        $S = self::bytesToNum(substr($signature, 32, 32));
        if (bccomp($S, self::L) >= 0) {
            return false;
        }

        $k = bcmod(self::bytesToNum(Blake2b::hash($Renc . $publicKey . $message, 64)), self::L);

        // Check S*B == R + k*A
        $left  = self::encodePoint(self::scalarMultBase($S));
        $right = self::encodePoint(self::pointAdd($R, self::scalarMult($k, $A)));

        return hash_equals($left, $right);
    }


    // *
    // *  Field helpers (decimal strings via bcmath)
    // *

    private static function modp(string $x): string
    {
        $r = bcmod($x, self::P);
        if (bccomp($r, '0') < 0) {
            $r = bcadd($r, self::P);
        }
        return $r;
    }

    private static function mulmod(string $a, string $b): string
    {
        return bcmod(bcmul($a, $b), self::P);
    }

    private static function inv(string $x): string
    {
        return bcpowmod($x, self::PM2, self::P);
    }


    // *
    // *  Point arithmetic, extended homogeneous coordinates (X, Y, Z, T)
    // *

    private static function pointAdd(array $p, array $q): array
    {
        [$x1, $y1, $z1, $t1] = $p;
        [$x2, $y2, $z2, $t2] = $q;

        $a = self::mulmod(self::modp(bcsub($y1, $x1)), self::modp(bcsub($y2, $x2)));
        $b = self::mulmod(self::modp(bcadd($y1, $x1)), self::modp(bcadd($y2, $x2)));
        $c = self::mulmod(self::mulmod($t1, self::D2), $t2);
        $d = self::mulmod(self::mulmod($z1, '2'), $z2);
        $e = self::modp(bcsub($b, $a));
        $f = self::modp(bcsub($d, $c));
        $g = self::modp(bcadd($d, $c));
        $h = self::modp(bcadd($b, $a));

        return [
            self::mulmod($e, $f),
            self::mulmod($g, $h),
            self::mulmod($f, $g),
            self::mulmod($e, $h),
        ];
    }

    private static function pointDouble(array $p): array
    {
        // dbl-2008-hwcd: A = X^2, B = Y^2, C = 2*Z^2, H = A+B,
        // E = H-(X+Y)^2, G = A-B, F = C+G
        [$x, $y, $z] = $p;

        $a = self::mulmod($x, $x);
        $b = self::mulmod($y, $y);
        $c = self::mulmod('2', self::mulmod($z, $z));
        $h = self::modp(bcadd($a, $b));
        $xy = self::modp(bcadd($x, $y));
        $e = self::modp(bcsub($h, self::mulmod($xy, $xy)));
        $g = self::modp(bcsub($a, $b));
        $f = self::modp(bcadd($c, $g));

        return [
            self::mulmod($e, $f),
            self::mulmod($g, $h),
            self::mulmod($f, $g),
            self::mulmod($e, $h),
        ];
    }

    /** Identity element */
    private static function pointZero(): array
    {
        return ['0', '1', '1', '0'];
    }

    /**
     * Scalar multiplication k*P, double-and-add (MSB first).
     * $k is a decimal string scalar.
     */
    private static function scalarMult(string $k, array $p): array
    {
        $bits = self::numToBits($k);
        $q = self::pointZero();

        foreach ($bits as $bit) {
            $q = self::pointDouble($q);
            if ($bit) {
                $q = self::pointAdd($q, $p);
            }
        }

        return $q;
    }

    private static function scalarMultBase(string $k): array
    {
        return self::scalarMult($k, [self::BX, self::BY, '1', self::mulmod(self::BX, self::BY)]);
    }


    // *
    // *  Point encoding / decoding (RFC 8032 §5.1.2 / §5.1.3)
    // *

    private static function encodePoint(array $p): string
    {
        $zi = self::inv($p[2]);
        $x  = self::mulmod($p[0], $zi);
        $y  = self::mulmod($p[1], $zi);

        $bytes = self::numToBytes($y, 32);
        if (bcmod($x, '2') == '1') {
            $bytes[31] = chr(ord($bytes[31]) | 0x80);
        }

        return $bytes;
    }

    private static function decodePoint(string $bytes): ?array
    {
        if (strlen($bytes) != 32) {
            return null;
        }

        $sign = (ord($bytes[31]) & 0x80) >> 7;
        $bytes[31] = chr(ord($bytes[31]) & 0x7f);
        $y = self::bytesToNum($bytes);

        if (bccomp($y, self::P) >= 0) {
            return null;
        }

        // Recover x: x^2 = (y^2 - 1) / (d*y^2 + 1)
        $y2 = self::mulmod($y, $y);
        $u  = self::modp(bcsub($y2, '1'));
        $v  = self::modp(bcadd(self::mulmod(self::D, $y2), '1'));

        $t = self::mulmod($u, self::inv($v));
        $x = bcpowmod($t, self::P38, self::P);

        if (self::mulmod($x, $x) != $t) {
            $x = self::mulmod($x, self::SQRT_M1);
            if (self::mulmod($x, $x) != $t) {
                return null;
            }
        }

        if ($x == '0' && $sign == 1) {
            return null;
        }

        if (bcmod($x, '2') != (string) $sign) {
            $x = bcsub(self::P, $x);
        }

        return [$x, $y, '1', self::mulmod($x, $y)];
    }


    // *
    // *  Conversions
    // *

    /** 32-byte little-endian to decimal string */
    private static function bytesToNum(string $bytes): string
    {
        $hex = bin2hex(strrev($bytes));
        $num = '0';
        // Process 8 hex digits (32 bits) at a time
        for ($i = 0, $len = strlen($hex); $i < $len; $i += 8) {
            $chunk = substr($hex, $i, 8);
            $num = bcadd(bcmul($num, bcpow('2', (string) (strlen($chunk) * 4))), (string) hexdec($chunk));
        }
        return $num;
    }

    /** Decimal string to fixed-size little-endian bytes */
    private static function numToBytes(string $num, int $size): string
    {
        $bytes = '';
        for ($i = 0; $i < $size; $i++) {
            $bytes .= chr((int) bcmod($num, '256'));
            $num = bcdiv($num, '256', 0);
        }
        if (bccomp($num, '0') != 0) {
            throw new Ed25519Blake2bException('Number does not fit in ' . $size . ' bytes');
        }
        return $bytes;
    }

    /** Decimal string to bit array, MSB first */
    private static function numToBits(string $num): array
    {
        $bits = [];
        while (bccomp($num, '0') > 0) {
            $bits[] = (int) bcmod($num, '2');
            $num = bcdiv($num, '2', 0);
        }
        return array_reverse($bits);
    }

    /** Apply Ed25519 clamping to the lower 32 bytes of the secret hash */
    private static function clamp(string $bytes): string
    {
        $bytes[0]  = chr(ord($bytes[0]) & 248);
        $bytes[31] = chr((ord($bytes[31]) & 127) | 64);
        return self::bytesToNum($bytes);
    }
}
