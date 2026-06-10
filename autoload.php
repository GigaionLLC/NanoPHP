<?php

/**
 * Standalone PSR-4 autoloader for GigaionLLC\NanoPHP.
 *
 * Use this when the library is used without Composer; the core classes
 * (NanoTool, NanoBlock, NanoRPC and the bundled crypto) have no external
 * dependencies beyond 64-bit PHP with bcmath.
 *
 *   require '/path/to/NanoPHP/autoload.php';
 */

spl_autoload_register(function (string $class): void {
    $prefix = 'GigaionLLC\\NanoPHP\\';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

    if (is_file($file)) {
        require $file;
    }
});
