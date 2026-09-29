<?php

namespace GigaionLLC\NanoPHP;

use \Exception;

class NanoRPCExtException extends Exception{}

class NanoRPCExt extends NanoRPC
{
    // *
    // *  Wallet sweep
    // *
    
    public function wallet_sweep(array $args)
    {
        // Check args
        if (!isset($args['wallet']) || !isset($args['destination'])) {
            $this->error = 'Unable to parse Array';
            return false;
        }
        
        $wallet      = $args['wallet'];
        $destination = $args['destination'];
        
        // Wallet ok?
        $wallet_info = $this->wallet_info(['wallet' => $wallet]);
        
        if ($this->error != null) {
            $this->error = 'Bad wallet number';
            return false;
        }
        
        // Balance ok?
        if (bccomp($wallet_info['balance'], '1') < 0) {
            $this->error = 'Insufficient balance';
            return false;
        }

        // Destination ok?
        if (!NanoTool::account2public($destination, false)) {
            $this->error = 'Bad destination';
            return false;
        }

        // Any sort?
        $sort = isset($args['sort']) ? $args['sort'] : 'list';
        
        //
        
        $return = ['balances' => [], 'sent' => '0'];

        // Get wallet balances
        $args = [
            'wallet'    => $wallet,
            'threshold' => 1
        ];

        $wallet_balances = $this->wallet_balances($args);

        if ($wallet_balances === false || !isset($wallet_balances['balances']) || !is_array($wallet_balances['balances'])) {
            $this->error = 'Unable to get wallet balances';
            return false;
        }

        // Sort balances
        if ($sort == 'asc') {
            uasort($wallet_balances['balances'], function ($a, $b) {
                return bccomp($a['balance'], $b['balance']);
            });
        } elseif ($sort == 'desc') {
            uasort($wallet_balances['balances'], function ($a, $b) {
                return bccomp($b['balance'], $a['balance']);
            });
        } else {
            // Do nothing
        }
        
        // Sweep wallet
        foreach ($wallet_balances['balances'] as $account => $balances) {
            if ((string) $account === (string) $destination) {
                $return['balances'][$account] = [
                    'notice' => 'Skipped self send',
                    'amount' => $balances['balance']
                ];
                continue;
            }

            $return['balances'][$account] = $this->sendFromAccount($wallet, (string) $account, $destination, $balances['balance']);

            if (isset($return['balances'][$account]['block'])) {
                $return['sent'] = bcadd($return['sent'], $balances['balance']);
            }
        }

        $this->responseRaw = json_encode($return);
        $this->response    = $return;
        
        return $this->response;
    }
    
    public function wallet_wipe(array $args)
    {
        return $this->wallet_sweep($args);
    }
    
    
    // *
    // *  Wallet send
    // *
    
    public function wallet_send(array $args)
    {
        // Check args
        if (!isset($args['wallet']) || !isset($args['destination']) || !isset($args['amount'])) {
            $this->error = 'Unable to parse Array';
            return false;
        }
        
        $wallet      = $args['wallet'];
        $destination = $args['destination'];
        $amount      = $args['amount'];
        
        // Wallet ok?
        $wallet_info = $this->wallet_info(['wallet' => $wallet]);
        
        if ($this->error != null) {
            $this->error = 'Bad wallet number';
            return false;
        }
    
        // Destination ok?
        if (!NanoTool::account2public($destination, false)) {
            $this->error = 'Bad destination';
            return false;
        }
        
        // Amount ok?
        if (!ctype_digit($amount)) {
            $this->error = 'Bad amount';
            return false;
        }
        
        if (bccomp($amount, '1') < 0) {
            $this->error = 'Bad amount';
            return false;
        }

        if (bccomp($wallet_info['balance'], $amount) < 0) {
            $this->error = 'Insufficient balance';
            return false;
        }
        
        // Any sort?
        $sort = isset($args['sort']) ? $args['sort'] : 'list';
        
        //
        
        $return            = ['balances' => []];
        $selected_accounts = [];
        $amount_left       = $amount;
        $sent              = '0';

        // Get wallet balances
        $args = [
            'wallet'    => $wallet,
            'threshold' => 1
        ];

        $wallet_balances = $this->wallet_balances($args);

        if ($wallet_balances === false || !isset($wallet_balances['balances']) || !is_array($wallet_balances['balances'])) {
            $this->error = 'Unable to get wallet balances';
            return false;
        }

        // Sort balances
        if ($sort == 'asc') {
            uasort($wallet_balances['balances'], function ($a, $b) {
                return bccomp($a['balance'], $b['balance']);
            });
        } elseif ($sort == 'desc') {
            uasort($wallet_balances['balances'], function ($a, $b) {
                return bccomp($b['balance'], $a['balance']);
            });
        } else {
            // Do nothing
        }
        
        // Select accounts
        foreach ($wallet_balances['balances'] as $account => $balances) {
            if (bccomp($balances['balance'], $amount_left) >= 0) {
                $selected_accounts[$account] = $amount_left;
                $amount_left                 = '0';
            } else {
                $selected_accounts[$account] = $balances['balance'];
                $amount_left                 = bcsub($amount_left, $balances['balance']);
            }

            if (bccomp($amount_left, '0') <= 0) {
                break; // Amount reached
            }
        }

        // Send from selected accounts. 'amount' is what this account was
        // selected to contribute (not its whole balance).
        foreach ($selected_accounts as $account => $balance) {
            if ((string) $account === (string) $destination) {
                $return['balances'][$account] = [
                    'notice' => 'Skipped self send',
                    'amount' => $balance
                ];
                continue;
            }

            $return['balances'][$account] = $this->sendFromAccount($wallet, (string) $account, $destination, $balance);

            if (isset($return['balances'][$account]['block'])) {
                $sent = bcadd($sent, $balance);
            }
        }

        // Surface anything not sent: skipped self send, failed sends, or
        // wallet balances that fell short of the requested amount
        $return['sent']      = $sent;
        $return['shortfall'] = bcsub($amount, $sent);

        $this->responseRaw = json_encode($return);
        $this->response    = $return;
        
        return $this->response;
    }
    
     
    // *
    // *  One send for wallet_send / wallet_sweep
    // *

    /**
     * Returns ['block' => hash, 'amount' => raw] on success, or
     * ['error' => ..., 'amount' => raw] when the node reports an error or
     * returns no (or an empty) block hash.
     */
    private function sendFromAccount(string $wallet, string $account, string $destination, string $amount): array
    {
        $send = $this->send([
            'wallet'      => $wallet,
            'source'      => $account,
            'destination' => $destination,
            'amount'      => $amount,
            // Idempotency id: random, not time-based like uniqid()
            'id'          => bin2hex(random_bytes(16))
        ]);

        if ($send === false || empty($send['block']) || !is_string($send['block']) ||
            $send['block'] === NanoTool::EMPTY32_HEX
        ) {
            $failure = [
                'error'  => 'Bad send',
                'amount' => $amount
            ];
            if ($this->error) {
                $failure['reason'] = is_string($this->error) ? $this->error : (string) json_encode($this->error);
            }

            return $failure;
        }

        return [
            'block'  => $send['block'],
            'amount' => $amount
        ];
    }


    // *
    // *  Wallet weight
    // *
    
    public function wallet_weight(array $args)
    {
        // Check args
        if (!isset($args['wallet'])) {
            $this->error = 'Unable to parse Array';
            return false;
        }
        
        $wallet = $args['wallet'];
        
        // Wallet ok?
        $wallet_info = $this->wallet_info(['wallet' => $wallet]);
        
        if ($this->error != null) {
            $this->error = 'Bad wallet number';
            return false;
        }
        
        // Any sort?
        
        $sort = isset($args['sort']) ? $args['sort'] : 'list';
        
        //
        
        $return = ['weight' => '', 'weights' => []];
        $wallet_weight = '0';
        
        // Get wallet balances
        $args = [
            'wallet' => $wallet
        ];
        
        $wallet_accounts = $this->account_list($args);
        
        // Check every weight and sum them
        foreach ($wallet_accounts['accounts'] as $account) {
            $account_weight              = $this->account_weight(['account'=>$account]);
            $wallet_weight               = bcadd($wallet_weight, $account_weight['weight']);
            $return['weights'][$account] = (string) $account_weight['weight'];
        }

        $return['weight'] = $wallet_weight;
        
        // Sort weights
        if ($sort == 'asc') {
            uasort($return['weights'], function ($a, $b) {
                return bccomp($a, $b);
            });
        } elseif ($sort == 'desc') {
            uasort($return['weights'], function ($a, $b) {
                return bccomp($b, $a);
            });
        } else {
            // Do nothing
        }
        
        $this->responseRaw = json_encode($return);
        $this->response    = $return;
        
        return $this->response;
    }
}
