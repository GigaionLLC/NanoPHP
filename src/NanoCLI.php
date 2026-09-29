<?php

namespace GigaionLLC\NanoPHP;

use \Exception;

class NanoCLIException extends Exception{}

/**
 * Thin wrapper around the nano_node command line binary.
 *
 * Every call runs `<nano_node> --<method> --<key>=<value> ...` through the
 * shell. The method and option names must be plain identifiers
 * (lowercase letters, digits, underscores) and every value is passed as a
 * single shell-escaped argument, so caller data can never inject extra
 * shell syntax.
 *
 * Security note: arguments are visible to other local users (process list,
 * /proc/<pid>/cmdline) while nano_node runs. Do NOT pass secrets such as
 * seeds, private keys or wallet passwords through this class.
 */
class NanoCLI
{
    // * Settings
    
    private $pathToApp;
    private $id = 0;
    
    
    // * Results and debug
    
    public $response;
    public $status;
    public $error;
    
    
    // *
    // *  Initialization
    // *
    
    public function __construct(string $path_to_app = '/home/nano/nano_node')
    {
        $this->pathToApp = escapeshellarg($path_to_app);
    }

    
    // *
    // *  Call
    // *
    
    public function __call($method, array $params)
    {       
        $this->id++;      
        $this->response = null;
        $this->status   = null;
        $this->error    = null;
        
        if (!isset($params[0])) {
            $params[0] = [];
        }
        
        $command = $this->pathToApp . $this->buildArguments((string) $method, (array) $params[0]);
        
        $this->error = exec($command . ' 2>&1', $this->response, $this->status);
        
        if ($this->status == 0) {
            $this->error = null;
            return $this->response;
        } else {
            $this->response = null;
            return false;
        }
    }


    // *
    // *  Argument building
    // *

    /**
     * Build " --method --key=value ..." with validated names and each
     * value shell-escaped (the resulting argv is unchanged for benign input).
     */
    private function buildArguments(string $method, array $options): string
    {
        if (!self::validName($method)) {
            throw new NanoCLIException('Invalid method name (allowed: lowercase letters, digits, underscores)');
        }

        $request = ' --' . $method;

        foreach ($options as $key => $value) {
            if (!self::validName((string) $key)) {
                throw new NanoCLIException('Invalid option name (allowed: lowercase letters, digits, underscores)');
            }

            $request .= ' --' . $key . '=' . escapeshellarg((string) $value);
        }

        return $request;
    }

    private static function validName(string $name): bool
    {
        return preg_match('/^[a-z][a-z0-9_]*$/D', $name) === 1;
    }
}
