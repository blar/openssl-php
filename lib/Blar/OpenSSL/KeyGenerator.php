<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

/**
 * Class KeyGenerator
 *
 * @package Blar\OpenSSL
 */
class KeyGenerator {

    /**
     * @var string
     */
    private $digestAlgorithm = 'SHA-1';

    /**
     * @var int
     */
    private $type = OPENSSL_KEYTYPE_RSA;

    /**
     * @var int
     */
    private $bits = 2048;

    /**
     * @return string
     */
    public function getDigestAlgorithm(): string {
        return $this->digestAlgorithm;
    }

    /**
     * @param string $digestAlgorithm
     */
    public function setDigestAlgorithm(string $digestAlgorithm) {
        $this->digestAlgorithm = $digestAlgorithm;
    }

    /**
     * @return int OPENSSL_KEYTYPE_*
     */
    public function getType(): int {
        return $this->type;
    }

    /**
     * @param int $type OPENSSL_KEYTYPE_*
     */
    public function setType(int $type) {
        $this->type = $type;
    }

    /**
     * @return int
     */
    public function getBits(): int {
        return $this->bits;
    }

    /**
     * @param int $bits
     */
    public function setBits(int $bits) {
        $this->bits = $bits;
    }

    /**
     * @return PrivateKey
     */
    public function generate(): PrivateKey {
        $privateKey = openssl_pkey_new([
            'digest_alg' => $this->getDigestAlgorithm(),
            'private_key_type' => $this->getType(),
            'private_key_bits' => $this->getBits()
        ]);
        return new PrivateKey($privateKey);
    }

}
