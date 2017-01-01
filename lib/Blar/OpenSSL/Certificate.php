<?php

namespace Blar\OpenSSL;

use Blar\Common\StringTools;
use Blar\Hash\Hash;
use DateTime;
use RuntimeException;

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
     * @param string $fileName
     *
     * @return Certificate
     */
    public static function createFromFileName(string $fileName): Certificate {
        $content = file_get_contents($fileName);
        return static::createFromString($content);
    }

    /**
     * @param string $content
     *
     * @return Certificate
     */
    public static function createFromString(string $content): Certificate {
        $handle = openssl_x509_read($content);
        return new static($handle);
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
     * @param resource $handle Certificate
     */
    public function __construct($handle) {
        $this->setHandle($handle);
    }

    /**
     * @return void
     */
    public function __destruct() {
        $handle = $this->getHandle();
        if(static::isCertificateResource($handle)) {
            openssl_x509_free($handle);
        }
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
     * @param bool $verbose
     *
     * @return string
     */
    public function export(bool $verbose = FALSE): string {
        openssl_x509_export($this->getHandle(), $output, !$verbose);
        return $output;
    }

    /**
     * @param string $fileName
     * @param bool $verbose
     *
     * @return bool
     */
    public function exportToFile(string $fileName, bool $verbose = FALSE): bool {
        return openssl_x509_export_to_file(
            $this->getHandle(),
            $fileName,
            !$verbose
        );
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
     * @param bool $longNames
     *
     * @return array
     */
    public function getInfo(bool $longNames = FALSE): array {
        return openssl_x509_parse($this->getHandle(), !$longNames);
    }

    /**
     * Get the fingerprint from certificate.
     *
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
     * Get the public key from the certificate.
     *
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey {
        $publicKey = openssl_pkey_get_public($this->getHandle());
        return new PublicKey($publicKey);
    }

    /**
     * @return DateTime
     */
    public function getValidFrom(): DateTime {
        $info = $this->getInfo();
        return DateTime::createFromFormat('U', $info['validFrom_time_t']);
    }

    /**
     * @return DateTime
     */
    public function getValidUntil(): DateTime {
        $info = $this->getInfo();
        return DateTime::createFromFormat('U', $info['validTo_time_t']);
    }

    /**
     * @return int
     */
    public function getSerial(): int {
        $info = $this->getInfo();
        return $info['serialNumber'];
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function hasExtension(string $name): bool {
        return array_key_exists($name, $this->getExtensions());
    }

    /**
     * @return array
     */
    public function getExtensions(): array {
        $info = $this->getInfo();
        return $info['extensions'];
    }

    /**
     * @param string $name
     *
     * @return mixed
     */
    public function getExtension(string $name) {
        $extensions = $this->getExtensions();
        return $extensions[$name];
    }

}
