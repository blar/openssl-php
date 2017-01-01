<?php

namespace Blar\OpenSSL;

use Blar\Filesystem\File;
use RuntimeException;
use SplFileInfo;

/**
 * Secure archive for private key and certificate chain.
 *
 * Personal Information Exchange Syntax Standard
 *
 * @package Blar\OpenSSL
 * @link http://de.wikipedia.org/wiki/PKCS
 */
class Pkcs12 {

    /**
     * @var Certificate
     */
    protected $certificate;

    /**
     * @var PrivateKey
     */
    protected $privateKey;

    /**
     * @var Chain
     */
    protected $chain;

    /**
     * @param string $fileName
     * @param string $password
     *
     * @return Pkcs12
     */
    public static function loadFromFileName(string $fileName, string $password = NULL): Pkcs12 {
        $content = file_get_contents($fileName);
        return static::loadFromString($content, $password);
    }

    /**
     * @param string $content
     * @param string $password
     *
     * @return Pkcs12
     */
    public static function loadFromString(string $content, string $password = NULL): Pkcs12 {
        if(!openssl_pkcs12_read($content, $result, $password)) {
            throw new RuntimeException(OpenSSL::getLastError());
        }

        $pkcs12 = new Pkcs12();

        if(array_key_exists('cert', $result)) {
            $certificate = Certificate::createFromString($result['cert']);
            $pkcs12->setCertificate($certificate);
        }

        if(array_key_exists('pkey', $result)) {
            $privateKey = PrivateKey::loadFromString($result['pkey']);
            $pkcs12->setPrivateKey($privateKey);
        }

        if(array_key_exists('extracerts', $result)) {
            $chain = new Chain($result['extracerts']);
            $pkcs12->setChain($chain);
        }

        return $pkcs12;
    }

    /**
     * @return string
     */
    public function __toString(): string {
        return $this->export();
    }

    /**
     * @return bool
     */
    public function hasCertificate(): bool {
        return $this->certificate !== NULL;
    }

    /**
     * @return Certificate
     */
    public function getCertificate(): Certificate {
        return $this->certificate;
    }

    /**
     * @param Certificate $certificate
     */
    public function setCertificate(Certificate $certificate) {
        $this->certificate = $certificate;
    }

    /**
     * @return bool
     */
    public function hasPrivateKey(): bool {
        return !is_null($this->privateKey);
    }

    /**
     * @return PrivateKey
     */
    public function getPrivateKey(): PrivateKey {
        return $this->privateKey;
    }

    /**
     * @param PrivateKey $privateKey
     */
    public function setPrivateKey(PrivateKey $privateKey) {
        $this->privateKey = $privateKey;
    }

    /**
     * @return bool
     */
    public function hasChain(): bool {
        return !is_null($this->chain);
    }

    /**
     * @return Chain
     */
    public function getChain(): Chain {
        return $this->chain;
    }

    /**
     * @param Chain $chain
     */
    public function setChain(Chain $chain) {
        $this->chain = $chain;
    }

    /**
     * @return array
     */
    public function getOptions(): array {
        $options = [];
        if($this->hasChain()) {
            $options['extracerts'] = $this->getChain();
        }
        # Is this write only?
        # $options['friendly_name'] = 'My signed cert by CA certificate';
        return $options;
    }

    /**
     * @param string $password
     * @return string
     * @throws RuntimeException
     */
    public function export($password = NULL): string {
        $status = openssl_pkcs12_export($this->getCertificate(), $result, $this->getPrivateKey(), $password, $this->getOptions());
        if(!$status) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
        return $result;
    }

    /**
     * @param string $fileName
     * @param string $password
     *
     * @throws RuntimeException
     */
    public function exportToFile(string $fileName, string $password = NULL) {
        $status = openssl_pkcs12_export_to_file($this->getCertificate(), $fileName, $this->getPrivateKey(), $password, $this->getOptions());
        if(!$status) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
    }

}
