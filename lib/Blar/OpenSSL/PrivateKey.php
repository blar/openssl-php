<?php

namespace Blar\OpenSSL;

use Blar\Filesystem\File;
use RuntimeException;

/**
 * Class PrivateKey
 *
 * @package Blar\OpenSSL
 */
class PrivateKey extends Key {

    /**
     * @return string
     */
    public function __toString(): string {
        return $this->export();
    }

    /**
     * @param mixed $privateKey
     * @param string $password
     */
    public function load($privateKey, string $password = NULL) {
        parent::load($privateKey);
        if($privateKey instanceof File) {
            $privateKey = $privateKey->getContent();
        }
        if($privateKey instanceof SplFileInfo) {
            $privateKey = file_get_contents($privateKey);
        }
        if(is_string($privateKey)) {
            $handle = openssl_pkey_get_private($privateKey, $password);
            if(!$handle) {
                throw new RuntimeException(OpenSSL::getLastError());
            }
            $this->setHandle($handle);
        }
    }

    /**
     * @param string $password
     * @param array $config
     *
     * @return string
     */
    public function export(string $password = NULL, array $config = []): string {
        $status = openssl_pkey_export(
            $this->getHandle(),
            $output,
            $password,
            $config
        );
        if(!$status) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
        return $output;
    }

    /**
     * Speichert den Schlüssel als PEM.
     *
     * @param string $filename
     * @param string $password
     * @param array $config
     */
    public function exportToFile(string $filename, string $password = NULL, array $config = []) {
        $status = openssl_pkey_export_to_file(
            $this->getHandle(),
            $filename,
            $password,
            $config
        );
        if(!$status) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey {
        $details = $this->getDetails();
        if(!array_key_exists('key', $details)) {
            throw new RuntimeException('Public key not found');
        }
        return new PublicKey($details['key']);
    }

    /**
     * @param string $decrypted
     *
     * @return string
     */
    public function encrypt(string $decrypted): string {
        $status = openssl_private_encrypt($decrypted, $encrypted, $this);
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
        $status = openssl_private_decrypt($encrypted, $decrypted, $this);
        if(!$status) {
            throw new RuntimeException('Decrypt failed');
        }
        return $decrypted;
    }

}
