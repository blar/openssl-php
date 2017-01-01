<?php

namespace Blar\OpenSSL;

use Blar\Filesystem\File;
use RuntimeException;
use SplFileInfo;

/**
 * Class PrivateKey
 *
 * @package Blar\OpenSSL
 */
class PrivateKey extends Key {

    const TYPE_RSA = OPENSSL_KEYTYPE_RSA;

    const TYPE_DSA = OPENSSL_KEYTYPE_DSA;

    const TYPE_DH = OPENSSL_KEYTYPE_DH;

    const TYPE_EC = OPENSSL_KEYTYPE_EC;

    /**
     * @param string $fileName
     * @param null $password
     *
     * @return PrivateKey
     */
    public static function loadFromFileName(string $fileName, $password = NULL): PrivateKey {
        $content = file_get_contents($fileName);
        return static::loadFromString($content, $password);
    }

    /**
     * @param string $content
     * @param null $password
     *
     * @return PrivateKey
     */
    public static function loadFromString(string $content, $password = NULL): PrivateKey {
        $handle = openssl_pkey_get_private($content, $password);
        if(!$handle) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
        return new PrivateKey($handle);
    }

    /**
     * Get the key as string as PEM.
     *
     * @return string
     */
    public function __toString(): string {
        return $this->export();
    }

    /**
     * Export the key to a string as PEM.
     *
     * @param string $password
     *
     * @return string
     */
    public function export(string $password = NULL): string {
        $status = openssl_pkey_export(
            $this->getHandle(),
            $output,
            $password
        );
        if(!$status) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
        return $output;
    }

    /**
     * Export the key to a file as PEM.
     *
     * @param string $filename
     * @param string $password
     */
    public function exportToFile(string $filename, string $password = NULL) {
        $status = openssl_pkey_export_to_file(
            $this->getHandle(),
            $filename,
            $password
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
        return PublicKey::loadFromString($details['key']);
    }

    /**
     * Encrypt data with the private key. Can be decrypted with PublicKey::decrypt().
     *
     * @param string $decrypted
     *
     * @return string Encrypted data.
     */
    public function encrypt(string $decrypted): string {
        $status = openssl_private_encrypt($decrypted, $encrypted, $this);
        if(!$status) {
            throw new RuntimeException('Encrypt failed');
        }
        return $encrypted;
    }

    /**
     * Decrypt data.
     *
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

    /**
     * @param PrivateKey $privateKey
     *
     * @return bool
     */
    public function compareTo(PrivateKey $privateKey): bool {
        return (string) $this == (string) $privateKey;
    }

    /**
     * Get the size of the key.
     *
     * @return int
     */
    public function getBits(): int {
        $info = $this->getDetails();
        return $info['bits'];
    }

    /**
     * Get the type of the key.
     *
     * @return int OPENSSL_KEYTYPE_*
     */
    public function getType(): int {
        $info = $this->getDetails();
        return $info['type'];
    }

}
