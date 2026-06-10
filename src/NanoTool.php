<?php

namespace GigaionLLC\NanoPHP;

use \Exception;
use GigaionLLC\NanoPHP\Crypto\Blake2b;
use GigaionLLC\NanoPHP\Crypto\Ed25519Blake2b;

class NanoToolException extends Exception{}

class NanoTool
{
    // *
    // *  Constants
    // *

    const RAWS = [
        'unano' =>                '1000000000000000000',
        'mnano' =>             '1000000000000000000000',
         'nano' =>          '1000000000000000000000000',
        'knano' =>       '1000000000000000000000000000',
        'Mnano' =>    '1000000000000000000000000000000',
         'NANO' =>    '1000000000000000000000000000000',
        'Gnano' => '1000000000000000000000000000000000'
    ];

    const PREAMBLE_HEX = '0000000000000000000000000000000000000000000000000000000000000006';
    const EMPTY32_HEX  = '0000000000000000000000000000000000000000000000000000000000000000';
    const HARDENED     =  0x80000000;

    const ACCOUNT_ALPHABET = '13456789abcdefghijkmnopqrstuwxyz';

    private static $bip39Words;


    // *
    // *  Internal helpers
    // *

    private static function isHex(string $value, int $length = 0): bool
    {
        if ($length > 0 && strlen($value) != $length) {
            return false;
        }

        return strlen($value) % 2 == 0 && strlen($value) > 0 && ctype_xdigit($value);
    }

    private static function accountChecksum(string $public_key_bin): string
    {
        // 5-byte BLAKE2b of the public key, reversed
        return strrev(Blake2b::hash($public_key_bin, 5));
    }

    private static function bytes2bits(string $bytes): string
    {
        $bits = '';
        for ($i = 0, $len = strlen($bytes); $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($bytes[$i])), 8, '0', STR_PAD_LEFT);
        }

        return $bits;
    }

    private static function bits2bytes(string $bits): string
    {
        $bytes = '';
        for ($i = 0, $len = strlen($bits); $i < $len; $i += 8) {
            $bytes .= chr(bindec(substr($bits, $i, 8)));
        }

        return $bytes;
    }

    private static function base32Encode(string $bytes): string
    {
        // Nano base32: data is left-padded with zero bits to a multiple of 5
        $bits = self::bytes2bits($bytes);
        $bits = str_pad($bits, (int) (ceil(strlen($bits) / 5) * 5), '0', STR_PAD_LEFT);

        $encoded = '';
        for ($i = 0, $len = strlen($bits); $i < $len; $i += 5) {
            $encoded .= self::ACCOUNT_ALPHABET[bindec(substr($bits, $i, 5))];
        }

        return $encoded;
    }

    private static function base32Decode(string $encoded, int $bytes): string
    {
        $bits = '';
        for ($i = 0, $len = strlen($encoded); $i < $len; $i++) {
            $pos = strpos(self::ACCOUNT_ALPHABET, $encoded[$i]);
            if ($pos === false) {
                throw new NanoToolException("Invalid character in encoded string: {$encoded[$i]}");
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        // Drop the leading padding bits
        return self::bits2bytes(substr($bits, strlen($bits) - $bytes * 8));
    }

    private static function bip39WordList(): array
    {
        if (self::$bip39Words === null) {
            $file = __DIR__ . '/Util/bip39-english.txt';
            if (!is_file($file)) {
                throw new NanoToolException("BIP39 word list not found: $file");
            }

            $words = preg_split('/\s+/', trim(file_get_contents($file)));
            if (count($words) != 2048) {
                throw new NanoToolException("Invalid BIP39 word list: $file");
            }

            self::$bip39Words = $words;
        }

        return self::$bip39Words;
    }


    // *
    // *  Denomination to raw
    // *

    public static function den2raw($amount, string $denomination): string
    {
        if (!array_key_exists($denomination, self::RAWS)) {
            throw new NanoToolException("Invalid denomination: $denomination");
        }

        $raw_to_denomination = self::RAWS[$denomination];

        if ($amount == 0) {
            return '0';
        }

        if (strpos($amount, '.')) {
            $dot_pos = strpos($amount, '.');
            $number_len = strlen($amount) - 1;
            $raw_to_denomination = substr($raw_to_denomination, 0, -($number_len - $dot_pos));
        }

        $amount = str_replace('.', '', $amount) . str_replace('1', '', $raw_to_denomination);

        // Remove useless zeros from left
        while (substr($amount, 0, 1) == '0') {
            $amount = substr($amount, 1);
        }

        return $amount;
    }


    // *
    // *  Raw to denomination
    // *

    public static function raw2den(string $amount, string $denomination): string
    {
        if (!array_key_exists($denomination, self::RAWS)) {
            throw new NanoToolException("Invalid denomination: $denomination");
        }

        $raw_to_denomination = self::RAWS[$denomination];

        if ($amount == '0') {
            return '0';
        }

        $prefix_lenght = 39 - strlen($amount);

        $i = 0;

        while ($i < $prefix_lenght) {
            $amount = '0' . $amount;
            $i++;
        }

        $amount = substr_replace($amount, '.', -(strlen($raw_to_denomination)-1), 0);

        // Remove useless zeroes from left
        while (substr($amount, 0, 1) == '0' && substr($amount, 1, 1) != '.') {
            $amount = substr($amount, 1);
        }

        // Remove useless decimals
        while (substr($amount, -1) == '0') {
            $amount = substr($amount, 0, -1);
        }

        // Remove dot if all decimals are zeros
        if (substr($amount, -1) == '.') {
            $amount = substr($amount, 0, -1);
        }

        return $amount;
    }


    // *
    // *  Denomination to denomination
    // *

    public static function den2den($amount, string $denomination_from, string $denomination_to): string
    {
        if (!array_key_exists($denomination_from, self::RAWS)) {
            throw new NanoToolException("Invalid source denomination: $denomination_from");
        }
        if (!array_key_exists($denomination_to, self::RAWS)) {
            throw new NanoToolException("Invalid target denomination: $denomination_to");
        }

        $raw = self::den2raw($amount, $denomination_from);

        return self::raw2den($raw, $denomination_to);
    }


    // *
    // *  Account to public key
    // *

    public static function account2public(string $account, bool $get_public_key = true)
    {
        if (((strpos($account, 'xrb_1') === 0  ||
              strpos($account, 'xrb_3') === 0) &&
             strlen($account) == 64) ||
            ((strpos($account, 'nano_1') === 0  ||
              strpos($account, 'nano_3') === 0) &&
             strlen($account) == 65)
        ) {
            $crop = explode('_', $account)[1];

            if (preg_match('/^[13456789abcdefghijkmnopqrstuwxyz]+$/', $crop)) {
                $public_key = self::base32Decode(substr($crop, 0, 52), 32);
                $checksum   = self::base32Decode(substr($crop, 52, 8), 5);

                if (hash_equals(self::accountChecksum($public_key), $checksum)) {
                    if ($get_public_key) {
                        return strtoupper(bin2hex($public_key));
                    }

                    return true;
                }
            }
        }

        return false;
    }


    // *
    // *  Public key to account
    // *

    public static function public2account(string $public_key): string
    {
        if (!self::isHex($public_key, 64)) {
            throw new NanoToolException("Invalid public key: $public_key");
        }

        $public_key = hex2bin($public_key);

        return 'nano_' . self::base32Encode($public_key) . self::base32Encode(self::accountChecksum($public_key));
    }


    // *
    // *  Private key to public key
    // *

    public static function private2public(string $private_key): string
    {
        if (!self::isHex($private_key, 64)) {
            throw new NanoToolException("Invalid private key: $private_key");
        }

        return strtoupper(bin2hex(Ed25519Blake2b::publicKey(hex2bin($private_key))));
    }


    // *
    // *  String to burn account
    // *

    public static function string2burn(string $string, string $leading_char = '1', string $filling_char = '1'): string
    {
        if (!preg_match('/^[13456789abcdefghijkmnopqrstuwxyz]+$/', $string) || strlen($string) < 1 || strlen($string) > 51) {
            throw new NanoToolException("Invalid string: $string");
        }
        if ($leading_char != '1' && $leading_char != '3') {
            throw new NanoToolException("Invalid leading character: $leading_char");
        }
        if (!preg_match('/^[13456789abcdefghijkmnopqrstuwxyz]$/', $filling_char)) {
            throw new NanoToolException("Invalid filling character: $filling_char");
        }

        $string = $leading_char . $string . str_repeat($filling_char, (51 - strlen($string)));

        $public_key = self::base32Decode($string, 32);

        return 'nano_' . $string . self::base32Encode(self::accountChecksum($public_key));
    }


    // *
    // *  Get random keypair
    // *

    public static function keys(bool $get_account = false): array
    {
        $private_key = random_bytes(32);
        $public_key  = Ed25519Blake2b::publicKey($private_key);

        $keys = [
            strtoupper(bin2hex($private_key)),
            strtoupper(bin2hex($public_key))
        ];

        if ($get_account) {
            $keys[] = self::public2account($keys[1]);
        }

        return $keys;
    }


    // *
    // *  Seed to keypair (Blake2b)
    // *

    public static function seed2keys(string $seed, int $index = 0, bool $get_account = false): array
    {
        if (!self::isHex($seed, 64)) {
            throw new NanoToolException("Invalid seed: $seed");
        }
        if ($index < 0 || $index > 4294967295) {
            throw new NanoToolException("Invalid index: $index");
        }

        $private_key = strtoupper(bin2hex(
            Blake2b::hash(hex2bin($seed) . pack('N', $index), 32)
        ));
        $public_key = self::private2public($private_key);

        $keys = [$private_key, $public_key];

        if ($get_account) {
            $keys[] = self::public2account($public_key);
        }

        return $keys;
    }


    // *
    // *  Mnemonic words to hexadecimal string (BIP39)
    // *

    public static function mnem2hex(array $words): string
    {
        $mnem_count = count($words);

        if ($mnem_count != 12 &&
            $mnem_count != 15 &&
            $mnem_count != 18 &&
            $mnem_count != 21 &&
            $mnem_count != 24
        ) {
            throw new NanoToolException("Invalid words array count: not 12,15,18,21,24");
        }

        $bip39_words = self::bip39WordList();
        $bits = '';

        foreach ($words as $word) {
            $index = array_search($word, $bip39_words);
            if ($index === false) {
                throw new NanoToolException("Invalid mnemonic word: $word");
            }

            $bits .= str_pad(decbin($index), 11, '0', STR_PAD_LEFT);
        }

        $entropy_bits  = intdiv($mnem_count * 11 * 32, 33);
        $checksum_bits = $mnem_count * 11 - $entropy_bits;

        $entropy = self::bits2bytes(substr($bits, 0, $entropy_bits));

        // Verify checksum
        $check = self::bytes2bits(hash('sha256', $entropy, true));
        if (substr($bits, $entropy_bits) !== substr($check, 0, $checksum_bits)) {
            throw new NanoToolException("Invalid mnemonic checksum");
        }

        return strtoupper(bin2hex($entropy));
    }


    // *
    // *  Hexadecimal string to mnemonic words (BIP39)
    // *

    public static function hex2mnem(string $hex): array
    {
        $hex_length = strlen($hex);

        if (($hex_length != 32 &&
             $hex_length != 40 &&
             $hex_length != 48 &&
             $hex_length != 56 &&
             $hex_length != 64) ||
            !self::isHex($hex)
        ) {
            throw new NanoToolException("Invalid hexadecimal string: $hex");
        }

        $bip39_words = self::bip39WordList();

        $entropy = hex2bin($hex);
        $entropy_bits  = $hex_length * 4;
        $checksum_bits = intdiv($entropy_bits, 32);

        $bits = self::bytes2bits($entropy)
              . substr(self::bytes2bits(hash('sha256', $entropy, true)), 0, $checksum_bits);

        $mnemonic = [];
        for ($i = 0, $len = strlen($bits); $i < $len; $i += 11) {
            $mnemonic[] = $bip39_words[bindec(substr($bits, $i, 11))];
        }

        return $mnemonic;
    }


    // *
    // *  Mnemonic words to master seed (BIP39/44)
    // *

    public static function mnem2mseed(array $words, string $passphrase = ''): string
    {
        if (count($words) < 1) {
            throw new NanoToolException("Invalid words array count: less than 1");
        }

        $bip39_words = self::bip39WordList();

        foreach ($words as $word) {
            if (array_search($word, $bip39_words) === false) {
                throw new NanoToolException("Invalid mnemonic word: $word");
            }
        }

        return strtoupper(
            hash_pbkdf2('sha512', implode(' ', $words), 'mnemonic' . $passphrase, 2048, 128)
        );
    }


    // *
    // *  Master seed to keypair (BIP39/44)
    // *

    public static function mseed2keys(string $mseed, int $index = 0, bool $get_account = false): array
    {
        if (!self::isHex($mseed, 128)) {
            throw new NanoToolException("Invalid master seed: $mseed");
        }
        if ($index < 0 || $index > 4294967295) {
            throw new NanoToolException("Invalid index: $index");
        }

        // BIP44 path m/44'/165'/index' with all segments hardened (SLIP-0010 ed25519)
        $path = [44, 165, $index];

        $I     = hash_hmac('sha512', hex2bin($mseed), 'ed25519 seed', true);
        $HDKey = [substr($I, 0, 32), substr($I, 32, 32)];

        foreach ($path as $entry) {
            if ($entry >= self::HARDENED) {
                $entry -= self::HARDENED;
            }

            $data  = chr(0x00) . $HDKey[0] . pack('N', self::HARDENED + $entry);
            $I     = hash_hmac('sha512', $data, $HDKey[1], true);
            $HDKey = [substr($I, 0, 32), substr($I, 32, 32)];
        }

        $private_key = strtoupper(bin2hex($HDKey[0]));
        $keys = [$private_key, self::private2public($private_key)];

        if ($get_account) {
            $keys[] = self::public2account($keys[1]);
        }

        return $keys;
    }


    // *
    // *  Hash array of hexadecimals
    // *

    public static function hashHexs(array $hexs, int $size = 32): string
    {
        if (count($hexs) < 1) {
            throw new NanoToolException("Invalid hexadecimals array count: less than 1");
        }
        if ($size < 1 || $size > 64) {
            throw new NanoToolException("Invalid size: $size");
        }

        $b2b = new Blake2b($size);

        foreach ($hexs as $value) {
            if (!self::isHex($value)) {
                throw new NanoToolException("Invalid hexadecimal string: $value");
            }

            $b2b->update(hex2bin($value));
        }

        return strtoupper(bin2hex($b2b->digest()));
    }


    // *
    // *  Sign message
    // *

    public static function sign(string $msg, string $private_key): string
    {
        if (!self::isHex($msg)) {
            throw new NanoToolException("Invalid message: $msg");
        }
        if (!self::isHex($private_key, 64)) {
            throw new NanoToolException("Invalid private key: $private_key");
        }

        return strtoupper(bin2hex(
            Ed25519Blake2b::sign(hex2bin($msg), hex2bin($private_key))
        ));
    }


    // *
    // *  Validate signature
    // *

    public static function validSign(string $msg, string $sig, string $account)
    {
        if (!self::isHex($msg)) {
            throw new NanoToolException("Invalid message: $msg");
        }
        if (!self::isHex($sig, 128)) {
            throw new NanoToolException("Invalid signature: $sig");
        }
        $public_key = self::account2public($account);
        if (!$public_key) {
            throw new NanoToolException("Invalid account: $account");
        }

        $valid = Ed25519Blake2b::verify(hex2bin($msg), hex2bin($sig), hex2bin($public_key));

        if (!$valid) {
            return false;
        }

        return strtoupper($msg);
    }


    // *
    // *  Multiplier to difficulty
    // *

    public static function mult2diff(string $difficulty, float $multiplier): string
    {
        if (!self::isHex($difficulty, 16)) {
            throw new NanoToolException("Invalid difficulty: $difficulty");
        }
        if ($multiplier <= 0) {
            throw new NanoToolException("Invalid multiplier: $multiplier");
        }

        $two64 = '18446744073709551616';
        $diff  = self::hex2dec($difficulty);

        $delta = bcdiv(bcsub($two64, $diff), sprintf('%.12F', $multiplier), 0);
        $value = bcsub($two64, $delta);

        if (bccomp($value, '0') < 0) {
            $value = '0';
        }

        return strtolower(str_pad(self::dec2hex($value), 16, '0', STR_PAD_LEFT));
    }


    // *
    // *  Difficulty to multiplier
    // *

    public static function diff2mult(string $base_difficulty, string $difficulty): float
    {
        if (!self::isHex($base_difficulty, 16)) {
            throw new NanoToolException("Invalid base difficulty: $base_difficulty");
        }
        if (!self::isHex($difficulty, 16)) {
            throw new NanoToolException("Invalid difficulty: $difficulty");
        }

        $two64 = '18446744073709551616';

        return (float) bcdiv(
            bcsub($two64, self::hex2dec($base_difficulty)),
            bcsub($two64, self::hex2dec($difficulty)),
            12
        );
    }


    // *
    // *  Hexadecimal <-> decimal for arbitrary precision (bcmath)
    // *

    public static function hex2dec(string $hex): string
    {
        if (!ctype_xdigit($hex)) {
            throw new NanoToolException("Invalid hexadecimal string: $hex");
        }

        $dec = '0';
        for ($i = 0, $len = strlen($hex); $i < $len; $i += 8) {
            $chunk = substr($hex, $i, 8);
            $dec = bcadd(bcmul($dec, bcpow('2', (string) (strlen($chunk) * 4))), (string) hexdec($chunk));
        }

        return $dec;
    }

    public static function dec2hex(string $dec, int $bytes = 0): string
    {
        if (!ctype_digit($dec)) {
            throw new NanoToolException("Invalid decimal string: $dec");
        }

        $hex = '';
        while (bccomp($dec, '0') > 0) {
            $hex = sprintf('%08X', (int) bcmod($dec, '4294967296')) . $hex;
            $dec = bcdiv($dec, '4294967296', 0);
        }

        $hex = ltrim($hex, '0');
        if ($hex === '') {
            $hex = '0';
        }
        if (strlen($hex) % 2 != 0) {
            $hex = '0' . $hex;
        }
        if ($bytes > 0) {
            $hex = str_pad($hex, $bytes * 2, '0', STR_PAD_LEFT);
        }

        return $hex;
    }


    // *
    // *  Generate work
    // *

    public static function work(string $hash, string $difficulty): string
    {
        if (!self::isHex($hash, 64)) {
            throw new NanoToolException("Invalid hash: $hash");
        }
        if (!self::isHex($difficulty, 16)) {
            throw new NanoToolException("Invalid difficulty: $difficulty");
        }

        $hash       = hex2bin($hash);
        $difficulty = hex2bin($difficulty);

        $nonce = random_bytes(8);

        while (true) {
            // Work value = BLAKE2b-8(nonce_LE || hash), interpreted little-endian
            $output = strrev(Blake2b::hash($nonce . $hash, 8));

            if (strcmp($output, $difficulty) >= 0) {
                return strtoupper(bin2hex(strrev($nonce)));
            }

            $nonce = strrev($output);
        }
    }


    // *
    // *  Validate work
    // *

    public static function validWork(string $hash, string $difficulty, string $work): bool
    {
        if (!self::isHex($hash, 64)) {
            throw new NanoToolException("Invalid hash: $hash");
        }
        if (!self::isHex($difficulty, 16)) {
            throw new NanoToolException("Invalid difficulty: $difficulty");
        }
        if (!self::isHex($work, 16)) {
            throw new NanoToolException("Invalid work: $work");
        }

        $output = strrev(Blake2b::hash(strrev(hex2bin($work)) . hex2bin($hash), 8));

        return strcmp($output, hex2bin($difficulty)) >= 0;
    }
}
