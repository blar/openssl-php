<?php

namespace Blar\OpenSSL;

class PrivateKey {

    public $handle;

    public static function create($config = array()) {
        $privateKey = new static();
        $privateKey->setHandle(openssl_pkey_new($config));
        return $privateKey;
    }

    public static function loadFile($fileName, $password = NULL) {
        $privateKey = new static();
        $privateKey->setHandle(openssl_pkey_get_private($fileName, $password));
        return $privateKey;
    }

    public static function loadString($string, $password = NULL) {
        $privateKey = new static();
        $privateKey->setHandle(openssl_pkey_get_private($string, $password));
        return $privateKey;
    }

    public function __destruct() {
        openssl_pkey_free($this->handle);
    }

    /**
     * @return string
     */
    public function __toString() {
        return $this->export();
    }

    /**
     * @param resource $handle
     * @return $this
     */
    public function setHandle($handle) {
        $this->handle = $handle;
        return $this;
    }

    /**
     * @return resource
     */
    public function getHandle() {
        return $this->handle;
    }

    /**
     * Speichert den Schlüssel als PEM.
     *
     * @param string $filename
     * @param string $password
     * @param array $config
     * @return $this
     */
    public function exportToFile($filename, $password = NULL, $config = array()) {
        openssl_pkey_export_to_file($this->handle, $filename, $password, $config);
        return $this;
    }

    /**
     * @param string $password
     * @param array $config
     * @return string
     */
    public function export($password = NULL, $config = array()) {
        openssl_pkey_export($this->handle, $output, $password, $config);
        return $output;
    }

    /**
     * @return array
     */
    public function getDetails() {
        $details = openssl_pkey_get_details($this->handle);
        /* Die Details enthalten Steuerzeichen, darum erst einmal nicht druchbare Zeichen per base64_encode verarbeiten. */
        array_walk_recursive($details, function (&$data) {
            if(!ctype_print($data)) {
                $data = base64_encode($data);
            }
        });
        return $details;
    }

    /**
     * @param null $password
     * @return bool|resource
     */
    public function getPrivateKey($password = NULL) {
        return $this->export($password);
    }

    /**
     * @param $certificate
     * @return resource
     */
    public function getPublicKey() {
        $details = $this->getDetails();
        return $details['key'];
    }

}
