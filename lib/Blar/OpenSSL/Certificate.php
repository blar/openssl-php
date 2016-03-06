<?php

namespace Blar\OpenSSL;

use Blar\Common\StringTools;
use Blar\Hash\Hash;
use Blar\OpenSSL\PublicKey;
use RuntimeException;
use SplFileInfo;

/**
 * Class Certificate
 *
 * @package Blar\OpenSSL
 */
class Certificate {

    /**
     * Binary-Format
     */
    const FORMAT_DER = 'der';

    /**
     * ASCII-Format (Base64)
     */
    const FORMAT_PEM = 'pem';

    /**
     * @var resource
     */
    private $handle;

    /**
     * @param string|resource $certificate Certificate
     */
    public function __construct($certificate = NULL) {
        $this->load($certificate);
    }

    /**
     * @param mixed $certificate
     *
     * @return bool
     */
    public static function isDerFormat($certificate): bool {
        return !self::isPemFormat($certificate);
    }

    /**
     * @param string $der
     *
     * @return string
     */
    public static function convertDerToPem(string $der): string {
        $encoded = base64_encode($der);
        $encoded = chunk_split($encoded, 64, "\n");
        return sprintf(
            "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n",
            $encoded
        );
    }

    /**
     * @param mixed $certificate
     *
     * @return bool
     */
    public static function isPemFormat($certificate): bool {
        if(!is_string($certificate)) {
            return FALSE;
        }
        return StringTools::contains(
            $certificate,
            '-----BEGIN CERTIFICATE-----'
        );
    }

    /**
     * @param string $pem
     *
     * @return string
     */
    public static function convertPemToDer(string $pem): string {
        return base64_decode(
            strtr(
                $pem,
                [
                    '-----BEGIN CERTIFICATE-----' => '',
                    '-----END CERTIFICATE-----' => ''
                ]
            )
        );
    }

    /**
     * @param mixed $resource
     *
     * @return bool
     */
    protected static function isCertificateResource($resource): bool {
        if(!is_resource($resource)) {
            return FALSE;
        }
        if(get_resource_type($resource) != 'OpenSSL X.509') {
            return FALSE;
        }
        return TRUE;
    }

    /**
     * @param string|resource|SplFileInfo $certificate
     */
    public function load($certificate) {
        if(is_resource($certificate)) {
            $this->setHandle($certificate);
            return;
        }
        if($certificate instanceof SplFileInfo) {
            $certificate = file_get_contents($certificate);
        }
        if(self::isDerFormat($certificate)) {
            $certificate = self::convertDerToPem($certificate);
        }
        if(is_string($certificate)) {
            $handle = openssl_x509_read($certificate);
            $this->setHandle($handle);
        }
    }

    public function __destruct() {
        $handle = $this->getHandle();
        if(!self::isCertificateResource($handle)) {
            return FALSE;
        }
        openssl_x509_free($handle);
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
        if(!self::isCertificateResource($handle)) {
            throw new RuntimeException(
                'Handle is not an OpenSSL X.509 resource'
            );
        }
        $this->handle = $handle;
    }

    /**
     * @return string
     */
    public function __toString(): string {
        return $this->export();
    }

    /**
     * @param string $format
     * @param bool $verbose
     *
     * @return string
     */
    public function export(string $format = self::FORMAT_PEM, bool $verbose = FALSE): string {
        openssl_x509_export($this->getHandle(), $output, !$verbose);
        if($format == self::FORMAT_DER) {
            $output = self::convertPemToDer($output);
        }
        return $output;
    }

    /**
     * Checks if a private key corresponds to a certificate.
     *
     * @param PrivateKey $privateKey
     *
     * @return bool
     */
    public function checkPrivateKey(PrivateKey $privateKey): bool {
        return openssl_x509_check_private_key($this->getHandle(), $privateKey);
    }

    /**
     * @param int $purpose X509_PURPOSE_*
     * @param array $cainfo
     * @param string $untrusted
     *
     * @return bool
     */
    public function checkPurpose(int $purpose, array $cainfo = [], string $untrusted = NULL): bool {
        if($untrusted === NULL) {
            $status = openssl_x509_checkpurpose($this->getHandle(), $purpose, $cainfo);
        }
        else {
            $status = openssl_x509_checkpurpose($this->getHandle(), $purpose, $cainfo, $untrusted);
        }
        if(!is_bool($status)) {
            throw new RuntimeException('Failed to check purpose');
        }
        return $status;
    }

    /**
     * @param string $fileName
     * @param string $format
     * @param bool $verbose
     *
     * @return bool
     */
    public function exportToFile(string $fileName, string $format = self::FORMAT_PEM, bool $verbose = FALSE): bool {
        return openssl_x509_export_to_file(
            $this->getHandle(),
            $fileName,
            !$verbose
        );
    }

    /**
     * @param bool $longNames
     *
     * @return array
     */
    public function getInfo(bool $longNames = FALSE): array {
        return openssl_x509_parse($this->getHandle(), !$longNames);
    }

    /**
     * @param string $algorithm
     *
     * @return Hash
     */
    public function getFingerprint(string $algorithm = 'SHA1'): Hash {
        $value = openssl_x509_fingerprint(
            $this->getHandle(),
            $algorithm,
            TRUE
        );
        if(!$value) {
            throw new RuntimeException(OpenSSL::getLastError());
        }

        $hash = new Hash($algorithm);
        $hash->setValue($value);
        return $hash;
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey {
        $publicKey = openssl_pkey_get_public($this->getHandle());
        return new PublicKey($publicKey);
    }

}
