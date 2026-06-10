<?php

if (file_exists(__DIR__ . '/../../../autoload.php')) {
    // Installed via Composer as a dependency
    require __DIR__ . '/../../../autoload.php';
} elseif (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require __DIR__ . '/../vendor/autoload.php';
} else {
    // No Composer: use the bundled standalone autoloader
    require __DIR__ . '/../autoload.php';
}
