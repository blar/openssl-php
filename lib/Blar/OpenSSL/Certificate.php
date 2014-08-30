<?php

namespace Blar\OpenSSL;

class Certificate {

    protected $handle;

    /**
     * @param string|resource $certificate Certificate
     */
    public function __construct($certificate) {
        if(is_resource($certificate)) {
            $this->handle = $certificate;
        }
        if(is_string($certificate)) {
            $this->handle = openssl_x509_read($certificate);
        }
    }

    public function __destruct() {
        openssl_x509_free($this->handle);
    }

    public function __toString() {
        return $this->export();
    }

    /**
     * @param string $privateKey
     * @return bool
     */
    public function checkPrivateKey($privateKey) {
        return openssl_x509_check_private_key($this->handle, $privateKey);
    }

    public function checkPurpose($purpose, $cainfo = array(), $untrusted = NULL) {
        return openssl_x509_checkpurpose($this->handle, $purpose, $cainfo, $untrusted);
    }

    public function exportToFile($filename, $verbose = false) {
        return openssl_x509_export_to_file($this->handle, $filename, !$verbose);
    }

    public function export($verbose = false) {
        openssl_x509_export($this->handle, $output, !$verbose);
        return $output;
    }

    public function parse($shortnames = true) {
        return openssl_x509_parse($this->handle, $shortnames);
    }

    public function getFingerprint($algorithm  = 'SHA1', $raw = false) {
        return openssl_x509_fingerprint($this->handle, $algorithm, $raw);
    }
}
