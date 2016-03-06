<?php

namespace Blar\OpenSSL;

use Blar\Filesystem\File;
use Exception;
use SplFileInfo;

/**
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
     */
    public function __construct(string $fileName = NULL, string $password = NULL) {
        $this->load($fileName, $password);
    }

    /**
     * @return string
     */
    public function __toString(): string {
        return $this->export();
    }

    /**
     * @param string $pkcs12
     * @param string $password
     *
     * @throws Exception
     */
    public function load($pkcs12, string $password = NULL) {
        if(is_null($pkcs12)) {
            return;
        }

        if($pkcs12 instanceof File) {
            $pkcs12 = $pkcs12->getContent();
        }

        if($pkcs12 instanceof SplFileInfo) {
            $pkcs12 = file_get_contents($pkcs12);
        }

        if(!openssl_pkcs12_read($pkcs12, $result, $password)) {
            throw new Exception(OpenSSL::getLastError());
        }

        if(array_key_exists('cert', $result)) {
            $certificate = new Certificate($result['cert']);
            $this->setCertificate($certificate);
        }

        if(array_key_exists('pkey', $result)) {
            $privateKey = new PrivateKey($result['pkey']);
            $this->setPrivateKey($privateKey);
        }

        if(array_key_exists('extracerts', $result)) {
            $this->setChain($result['extracerts']);
        }
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
        return $this->privateKey !== NULL;
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
        return $this->chain !== NULL;
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
     * @param string $password
     * @return string
     * @throws RuntimeException
     */
    public function export($password = NULL) {
        $options = [];
        if($this->hasChain()) {
            $options['extracerts'] = $this->getChain();
        }
        $status = openssl_pkcs12_export($this->getCertificate(), $result, $this->getPrivateKey(), $password, $options);
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
        $options = [];
        if($this->hasChain()) {
            $options['extracerts'] = $this->getChain();
        }
        $status = openssl_pkcs12_export_to_file($this->getCertificate(), $fileName, $this->getPrivateKey(), $password, $options);
        if(!$status) {
            throw new RuntimeException(OpenSSL::getLastError());
        }
    }

}
