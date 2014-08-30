<?php

namespace Blar\OpenSSL;

class OpenSSL {

    /**
     * @param integer $length
     * @param boolean $strong
     * @return string
     */
    public static function getPseudoRandomBytes($length, &$strong) {
        return openssl_random_pseudo_bytes($length, $strong);
    }

    /**
     * @param boolean $aliases
     * @return array
     */
    public static function getCipherMethods($aliases = false) {
        return openssl_get_cipher_methods($aliases);
    }

    /**
     * @param mixed $method
     * @return integer
     */
    public static function getCipherIvLength($method) {
        return openssl_cipher_iv_length($method);
    }

    /**
     * @param boolean $aliases
     * @return array
     */
    public static function getDigestMethods($aliases = false) {
        return openssl_get_md_methods($aliases);
    }

    /**
     * @param string $data
     * @param mixed $method
     * @param boolean $raw
     * @return string
     */
    public static function digest($data, $method, $raw = false) {
        return openssl_digest($data, $method, $raw);
    }

    public static function getLastError() {
        return openssl_error_string();
    }

}
