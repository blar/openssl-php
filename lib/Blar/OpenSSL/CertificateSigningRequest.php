<?php

namespace Blar\OpenSSL;

/**
 * Class CertificateSigningRequest
 *
 * @package Blar\OpenSSL
 */
class CertificateSigningRequest {

    /**
     * @var resource
     */
    private $handle;

    /**
     * @var Certificate
     */
    private $certificate;

    /**
     * @var PrivateKey
     */
    private $privateKey;

    /**
     * @var Subject
     */
    private $subject;

    /**
     * @return string
     */
    public function __toString(): string {
        return $this->export();
    }

    /**
     * @param bool $verbose
     *
     * @return string
     */
    public function export(bool $verbose = false): string {
        openssl_csr_export($this->getHandle(), $output, !$verbose);
        return $output;
    }

    /**
     * @return resource
     */
    public function getHandle() {
        return $this->handle;
    }

    /**
     * @param resource $handle
     *
     * @return $this
     */
    public function setHandle($handle) {
        $this->handle = $handle;
        return $this;
    }

    /**
     * @return Subject
     */
    public function getSubject(): Subject {
        return $this->subject;
    }

    /**
     * @param Subject $subject
     */
    public function setSubject(Subject $subject) {
        $this->subject = $subject;
    }

    /**
     * @param bool $longNames
     *
     * @return array
     */
    public function getSubject1(bool $longNames = false): array {
        return openssl_csr_get_subject($this->getHandle(), $longNames);
    }

    /**
     * @param bool $longNames
     *
     * @return PublicKey
     */
    public function getPublicKey(bool $longNames = false): PublicKey {
        $publicKey = openssl_csr_get_public_key($this->getHandle(), $longNames);
        return new PublicKey($publicKey);
    }

    /**
     * @param array $config
     * @param array $attributes
     */
    public function generate(array $config = [], array $attributes = []) {
        $privateKey = $this->getPrivateKey();
        $handle = openssl_csr_new($this->getSubject()->getArrayCopy(), $privateKey /*, $config, $attributes */);
        $this->setHandle($handle);
        # $this->setPrivateKey($privateKey);
    }

    /**
     * @param string $fileName
     * @param bool $verbose
     */
    public function exportToFile(string $fileName, bool $verbose = false) {
        openssl_csr_export_to_file($this->getHandle(), $fileName, !$verbose);
    }

    /**
     * Setzt Zertifikat und PrivateKey der CA anhand eines PKCS12.
     *
     * @param Pkcs12 $pkcs12
     */
    public function setPkcs12(Pkcs12 $pkcs12) {
        $this->setCertificate($pkcs12->getCertificate());
        $this->setPrivateKey($pkcs12->getPrivateKey());
    }

    /**
     * @param int $lifetime Lifetime in Days.
     * @param array $config
     * @param int $serial
     *
     * @return Certificate
     */
    public function sign(int $lifetime = 365, array $config = [], int $serial = 0): Certificate {
        $certificate = openssl_csr_sign(
            $this->getHandle(),
            $this->getCertificate(),
            $this->getPrivateKey(),
            $lifetime,
            $config,
            $serial
        );
        return new Certificate($certificate);
    }

    /**
     * @param int $lifetime In Days.
     * @param array $config
     * @param int $serial
     *
     * @return Certificate
     */
    public function selfSign(int $lifetime = 365, array $config = [], int $serial = 0): Certificate {
        $certificate = openssl_csr_sign(
            $this->getHandle(),
            NULL,
            $this->getPrivateKey(),
            $lifetime,
            $config,
            $serial
        );
        return new Certificate($certificate);
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
     * @return PrivateKey
     */
    public function getPrivateKey(): PrivateKey {
        return $this->privateKey;
    }

    /**
     * @param PrivateKey $privateKey
     *
     * @return $this
     */
    public function setPrivateKey(PrivateKey $privateKey) {
        $this->privateKey = $privateKey;
    }

}
