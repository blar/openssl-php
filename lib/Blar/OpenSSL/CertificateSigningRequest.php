<?php

namespace Blar\OpenSSL;

class CertificateSigningRequest {

    protected $handle;
    protected $privateKey;

    public function __construct($dn, $privateKey = NULL, $config = NULL, $attributes = NULL) {
        $this->handle = openssl_csr_new($dn, $privateKey, $config, $attributes);
        $this->setPrivateKey($privateKey);
    }

    public function __toString() {
        return $this->export();
    }

    public function setPrivateKey($privateKey) {
        $this->privateKey = PrivateKey::loadString($privateKey);
        return $this;
    }

    public function getPrivateKey() {
        return $this->privateKey;
    }

    public function getPublicKey($shortnames = TRUE) {
        return openssl_csr_get_public_key($this->handle, $shortnames);
    }

    public function exportToFile($filename, $verbose = false) {
        openssl_csr_export_to_file($this->handle, $filename, !$verbose);
        return $this;
    }

    public function export($verbose = false) {
        openssl_csr_export($this->handle, $output, !$verbose);
        return $output;
    }

    public function getSubject($shortnames = true) {
        return openssl_csr_get_subject($this->handle, $shortnames);
    }

    public function sign($certificate = NULL, $privateKey = NULL, $lifetime = 365, $config = array(), $serial = 0) {
        if(is_null($privateKey)) {
            $privateKey = $this->getPrivateKey();
        }
        $certificate = openssl_csr_sign($this->handle, $certificate, $privateKey, $lifetime, $config, $serial);
        return new Certificate($certificate);
    }

    public function selfSign($privateKey = NULL, $lifetime = 365, $config = array(), $serial = 0) {
        if(is_null($privateKey)) {
            $privateKey = $this->getPrivateKey();
        }
        return $this->sign(NULL, $privateKey, $lifetime, $config, $serial);
    }

}
