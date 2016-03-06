<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use Blar\Filesystem\File;
use RuntimeException;
use SplFileInfo;

/**
 * Class PublicKey
 *
 * @package Blar\OpenSSL
 */
class PublicKey extends Key {

    /**
     * @return string
     */
    public function __toString(): string {
        $details = $this->getDetails();
        return $details['key'];
    }

    /**
     * @param mixed $publicKey
     */
    public function load($publicKey) {
        parent::load($publicKey);
        if($publicKey instanceof File) {
            $publicKey = $publicKey->getContent();
        }
        if($publicKey instanceof SplFileInfo) {
            $publicKey = file_get_contents($publicKey);
        }
        if(is_string($publicKey)) {
            $handle = openssl_pkey_get_public($publicKey);
            if(!$handle) {
                throw new RuntimeException(OpenSSL::getLastError());
            }
            $this->setHandle($handle);
        }
    }

    /**
     * @param string $decrypted
     *
     * @return string
     */
    public function encrypt(string $decrypted): string {
        $status = openssl_public_encrypt($decrypted, $encrypted, $this);
        if(!$status) {
            throw new RuntimeException('Encrypt failed');
        }
        return $encrypted;
    }

    /**
     * @param string $encrypted
     *
     * @return string
     */
    public function decrypt(string $encrypted): string {
        $status = openssl_public_decrypt($encrypted, $decrypted, $this);
        if(!$status) {
            throw new RuntimeException('Decrypt failed');
        }
        return $decrypted;
    }

}
