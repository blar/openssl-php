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
     * CertificateSigningRequest constructor.
     *
     * @param string|resource $csr
     */
    public function __construct($csr) {
        $this->setHandle($csr);
    }

    /**
     * @return string
     */
    public function __toString(): string {
        return $this->export();
    }

    /**
     * @return resource
     */
    public function getHandle() {
        return $this->handle;
    }

    /**
     * @param resource $handle
     */
    public function setHandle($handle) {
        $this->handle = $handle;
    }

    /**
     * Export as string.
     *
     * @param bool $verbose Add additional text output.
     *
     * @return string
     */
    public function export(bool $verbose = false): string {
        openssl_csr_export($this->getHandle(), $output, !$verbose);
        return $output;
    }

    /**
     * Export to a file.
     *
     * @param string $fileName
     * @param bool $verbose Add additional text output.
     */
    public function exportToFile(string $fileName, bool $verbose = false) {
        openssl_csr_export_to_file($this->getHandle(), $fileName, !$verbose);
    }

    /**
     * @param bool $longNames
     *
     * @return array
     */
    public function getSubject(bool $longNames = false): array {
        return openssl_csr_get_subject($this->getHandle(), $longNames);
    }

    /**
     * Get public key.
     *
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey {
        $publicKey = openssl_csr_get_public_key($this->getHandle());
        return new PublicKey($publicKey);
    }

}
