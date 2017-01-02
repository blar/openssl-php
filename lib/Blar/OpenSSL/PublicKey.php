<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use RuntimeException;

/**
 * Class PublicKey
 *
 * @package Blar\OpenSSL
 */
class PublicKey extends Key {

    /**
     * @param string $fileName
     *
     * @return PublicKey
     */
    public static function loadFromFileName(string $fileName): PublicKey {
        $content = file_get_contents($fileName);
        return static::loadFromString($content);
    }

    /**
     * @param string $content
     *
     * @return PublicKey
     */
    public static function loadFromString(string $content): PublicKey {
        $handle = openssl_pkey_get_public($content);
        if(!$handle) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
        return new PublicKey($handle);
    }

    /**
     * @return string
     */
    public function __toString(): string {
        $details = $this->getDetails();
        return $details['key'];
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

    /**
     * @param PublicKey $privateKey
     *
     * @return bool
     */
    public function compareTo(PublicKey $privateKey): bool {
        return (string) $this == (string) $privateKey;
    }

    /**
     * @return string
     */
    protected function getDer() {
        $temp = strtr($this, [
            '-----BEGIN PUBLIC KEY-----' => '',
            '-----END PUBLIC KEY-----' => '',
            "\n" => ''
        ]);
        return base64_decode($temp);
    }

    /**
     * Get fingerprint
     * This is useful for public key pinning.
     *
     * @param string $format
     *
     * @return \Blar\Hash\Hash
     */
    public function getFingerprint($format = 'SHA256') {
        return OpenSSL::digest($this->getDer(), $format);
    }

}
