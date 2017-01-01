<?php

/**
 * CertificateSigningRequestSigner.php
 *
 * @since 2017-01-01
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

/**
 * Class CertificateSigningRequestSigner
 *
 * @package Blar\OpenSSL
 */
class CertificateSigningRequestSigner {

    /**
     * Private key of the certificate authority.
     *
     * @var PrivateKey
     */
    private $privateKey;

    /**
     * Certificate of the certificate authority.
     *
     * @var Certificate
     */
    private $certificate;

    /**
     * Lifetime of the created certificates.
     *
     * @var int in days.
     */
    private $lifetime = 365;

    /**
     * @var string
     */
    private $configFileName = '';

    /**
     * @var string
     */
    private $extensions = '';

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
     * Set private key and certificate of the certificate authority from PKCS12.
     *
     * @param Pkcs12 $pkcs12
     */
    public function setPkcs12(Pkcs12 $pkcs12) {
        $this->setCertificate($pkcs12->getCertificate());
        $this->setPrivateKey($pkcs12->getPrivateKey());
    }

    /**
     * @return int Days.
     */
    public function getLifetime(): int {
        return $this->lifetime;
    }

    /**
     * @param int $lifetime In days.
     */
    public function setLifetime(int $lifetime) {
        $this->lifetime = $lifetime;
    }


    /**
     * @return string
     */
    public function getExtensions(): string {
        return $this->extensions;
    }

    /**
     * Use additional section in the openssl config.
     *
     * @param string $extensions
     */
    public function setExtensions(string $extensions) {
        $this->extensions = $extensions;
    }

    /**
     * @return string
     */
    public function getConfigFileName(): string {
        return $this->configFileName;
    }

    /**
     * @param string $configFileName
     */
    public function setConfigFileName(string $configFileName) {
        $this->configFileName = $configFileName;
    }

    /**
     * @return array
     */
    protected function getOptions(): array {
        $options = [];
        if($this->getExtensions()) {
            $options['x509_extensions'] = $this->getExtensions();
        }
        if($this->getConfigFileName()) {
            $options['config'] = $this->getConfigFileName();
        }
        return $options;
    }

    /**
     * Create a new Certificate.
     *
     * @param CertificateSigningRequest $csr
     * @param int $serial
     *
     * @return Certificate
     */
    public function sign(CertificateSigningRequest $csr, int $serial = 0): Certificate {
        $certificate = openssl_csr_sign(
            $csr->export(),
            $this->getCertificate(),
            $this->getPrivateKey(),
            $this->getLifetime(),
            $this->getOptions(),
            $serial
        );
        return new Certificate($certificate);
    }

    /**
     * Create a self signed certificate.
     *
     * @param CertificateSigningRequest $csr
     * @param int $serial
     *
     * @return Certificate
     */
    public function selfSign(CertificateSigningRequest $csr, int $serial = 0): Certificate {
        $certificate = openssl_csr_sign(
            $csr->export(),
            NULL,
            $this->getPrivateKey(),
            $this->getLifetime(),
            $this->getOptions(),
            $serial
        );
        return new Certificate($certificate);
    }

}
