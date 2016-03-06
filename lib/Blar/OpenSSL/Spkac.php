<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

/**
 * Class Spkac
 *
 * @package Blar\OpenSSL
 */
class Spkac {

    /**
     * @var string
     */
    private $spkac;

    /**
     * @param PrivateKey $privateKey
     * @param string $challenge
     * @param string $algorithm
     *
     * @return Spkac
     */
    public static function create(PrivateKey $privateKey, string $challenge = NULL, string $algorithm = NULL): Spkac {
        $spkac = openssl_spki_new($privateKey, $challenge, $algorithm);
        return new static($spkac);
    }

    /**
     * @param string $spkac
     *
     * @return string
     */
    public static function normalize(string $spkac): string {
        return self::stripPrefix($spkac, 'SPKAC=');
    }

    /**
     * @param string $string
     * @param string $prefix
     *
     * @return string
     */
    protected static function stripPrefix(string $string, string $prefix): string {
        if(strpos($string, $prefix) !== 0) {
            return $string;
        }
        return substr($string, strlen($prefix));
    }

    /**
     * Spkac constructor.
     *
     * @param string $spkac
     */
    public function __construct(string $spkac) {
        $this->setSpkac($spkac);
    }

    /**
     * @return string
     */
    public function __toString(): string {
        return $this->getSpkac();
    }

    /**
     * @return string
     */
    public function getSpkac(): string {
        return $this->spkac;
    }

    /**
     * @param string $spkac
     */
    public function setSpkac(string $spkac) {
        $this->spkac = self::normalize($spkac);
    }

    /**
     * @return bool
     */
    public function verify(): bool {
        return openssl_spki_verify($this->getSpkac());
    }

    /**
     * @return string
     */
    public function getPublicKey(): string {
        return openssl_spki_export($this->getSpkac());
    }

    /**
     * @return string
     */
    public function getChallenge(): string {
        return openssl_spki_export_challenge($this->getSpkac());
    }

}
