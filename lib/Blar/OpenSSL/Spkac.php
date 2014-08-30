<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

class Spkac {

    protected $spkac;

    public function __construct($spkac) {
        if(substr($spkac, 0, 6) == 'SPKAC=') {
            $spkac = substr($spkac, 6);
        }
        $this->spkac = $spkac;
    }

    public function __toString() {
        return $this->spkac;
    }

    public static function create($privateKey, $challenge, $algorithm = NULL) {
        $spkac = openssl_spki_new($privateKey, $challenge, $algorithm);
        return new static($spkac);
    }

    public function verify() {
        return openssl_spki_verify($this->spkac);
    }

    public function exportPublicKey() {
        return openssl_spki_export($this->spkac);
    }

    public function exportChallenge() {
        return openssl_spki_export_challenge($this->spkac);
    }

}

