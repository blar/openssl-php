<?php

namespace Blar\OpenSSL;

use Blar\Hash\Hash;

/**
 * Class OpenSSL
 *
 * @package Blar\OpenSSL
 */
class OpenSSL {

    /**
     * @param int $length
     * @param bool $strong
     *
     * @return string
     */
    public static function getPseudoRandomBytes(int $length, bool &$strong = false): string {
        return openssl_random_pseudo_bytes($length, $strong);
    }

    /**
     * @param bool $aliases
     *
     * @return array
     */
    public static function getCipherMethods(bool $aliases = FALSE): array {
        return openssl_get_cipher_methods($aliases);
    }

    /**
     * @param string $method
     *
     * @return int
     */
    public static function getCipherIvLength(string $method): int {
        return openssl_cipher_iv_length($method);
    }

    /**
     * @param bool $aliases
     *
     * @return array
     */
    public static function getDigestMethods(bool $aliases = FALSE): array {
        return openssl_get_md_methods($aliases);
    }

    /**
     * @param string $data
     * @param string $algorithm
     *
     * @return Hash
     */
    public static function digest(string $data, string $algorithm): Hash {
        $hash = new Hash();
        $hash->setAlgorithm($algorithm);
        $hash->setValue(openssl_digest($data, $algorithm, TRUE));
        return $hash;
    }

    public static function clearErrors() {
        while(openssl_error_string());
    }

    /**
     * @return string
     */
    public static function getLastError(): string {
        $messages = self::getErrors();
        return array_pop($messages);
    }

    /**
     * @return array
     */
    public static function getErrors(): array {
        $messages = [];
        while($message = openssl_error_string()) {
            $messages[] = $message;
        }
        return $messages;
    }

    /**
     * @return array
     */
    public static function getCertificateLocations(): array {
        return openssl_get_cert_locations();
    }

}
