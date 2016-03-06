<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use Blar\Filesystem\TempFile;
use RuntimeException;

/**
 * Class Pkcs7
 *
 * @package Blar\OpenSSL
 * @link http://de.wikipedia.org/wiki/PKCS
 */
class Pkcs7 {

    /**
     * Binary-Format
     */
    const FORMAT_DER = 'der';

    /**
     * ASCII-Format (Base64)
     */
    const FORMAT_PEM = 'pem';

    /**
     * SMIME-Format
     */
    const FORMAT_SMIME = 'smime';

    /**
     * @var Certificate
     */
    private $certificate;

    /**
     * @var PrivateKey
     */
    private $privateKey;

    /**
     * @var Certificate
     */
    private $chain;

    /**
     * @var array
     */
    private $headers = [];

    /**
     * @var int
     */
    private $flags;

    /**
     * @param string $message
     * @param string $signature
     *
     * @return string
     */
    public static function createMime(string $message, string $signature): string {
        $message = file_get_contents($message);
        $signature = file_get_contents($signature);
        if(!ctype_print($signature)) {
            $signature = chunk_split(base64_encode($signature), 64, "\n");
        }
        $result[] = 'MIME-Version: 1.0';
        $result[] = 'Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha1"; boundary="----514017AE3B7DB78049DEB1F0D4599106"';
        $result[] = '';
        $result[] = 'This is an S/MIME signed message';
        $result[] = '';
        $result[] = '------514017AE3B7DB78049DEB1F0D4599106';
        $result[] = $message;
        $result[] = '------514017AE3B7DB78049DEB1F0D4599106';
        $result[] = 'Content-Type: application/x-pkcs7-signature; name="smime.p7s"';
        $result[] = 'Content-Transfer-Encoding: base64';
        $result[] = 'Content-Disposition: attachment; filename="smime.p7s"';
        $result[] = '';
        $result[] = $signature;
        $result[] = '------514017AE3B7DB78049DEB1F0D4599106--';
        return implode("\n", $result);
    }

    /**
     * Setzt das Zertifikat, den Private Key und die Chain anhand eines PKCS12.
     *
     * @param Pkcs12 $pkcs12
     */
    public function setPkcs12(Pkcs12 $pkcs12) {
        $this->setCertificate($pkcs12->getCertificate());
        $this->setPrivateKey($pkcs12->getPrivateKey());
        $this->setChain($pkcs12->getChain());
    }

    /**
     * @param string $message
     * @param string $format
     *
     * @return string
     */
    public function sign(string $message, $format = self::FORMAT_PEM) {
        $inputFileName = new TempFile('smime_unsigned_');
        $inputFileName->setContent($message);

        $chainFile = new TempFile('smime_chain_');
        $chainFile->setContent($this->getChain());

        $outputFileName = new TempFile('smime_signed_');

        openssl_pkcs7_sign(
            $inputFileName,
            $outputFileName,
            $this->getCertificate(),
            $this->getPrivateKey(),
            $this->getHeaders(),
            $this->getFlags() /*, $chainFile */
        );
        $signature = $outputFileName->getContent();

        if($format != self::FORMAT_SMIME) {
            $signature = $this->extractSignature($signature);
        }

        if($format == self::FORMAT_DER) {
            $signature = base64_decode($signature);
        }

        return $signature;
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
     */
    public function setPrivateKey(PrivateKey $privateKey) {
        $this->privateKey = $privateKey;
    }

    /**
     * @return array
     */
    public function getHeaders(): array {
        return $this->headers;
    }

    /**
     * @param array $headers
     */
    public function setHeaders(array $headers) {
        $this->headers = $headers;
    }

    /**
     * @return int
     */
    public function getFlags(): int {
        return $this->flags;
    }

    /**
     * @param int $flags
     */
    public function setFlags(int $flags) {
        $this->flags = $flags;
    }

    /*
    public static function encrypt($message, $flags = 0, $cipher = OPENSSL_CIPHER_AES_256_CBC) {
        $inputFileName = tempnam(sys_get_temp_dir(), 'smime_decrypted_');
        file_put_contents($inputFileName, $message);

        $outputFileName = tempnam(sys_get_temp_dir(), 'smime_encrypted_');

        openssl_pkcs7_encrypt($inputFileName, $outputFileName, $certificates, $headers, $flags, $cipher);
        return file_get_contents($outputFileName);
    }

    public static function decrypt($message) {
        $inputFileName = tempnam(sys_get_temp_dir(), 'smime_encrypted_');
        file_put_contents($inputFileName, $message);

        $outputFileName = tempnam(sys_get_temp_dir(), 'smime_decrypted_');

        openssl_pkcs7_decrypt($inputFileName, $outputFileName, $certificates, $privateKey);
        return file_get_contents($outputFileName);
    }
    */

    /**
     * Extract Signature from SMIME
     *
     * @param string $content
     *
     * @return string mixed
     */
    protected function extractSignature($content) {
        $parts = explode("\n\n", $content);
        $signature = $parts[3];
        return $signature;
    }

    /**
     * @param string $mime
     * @param $chain
     *
     * @return bool
     */
    public function verify(string $mime, $chain): bool {
        $inputFileName = new TempFile('smime_signed_');
        $inputFileName->setContent($mime);

        $status = openssl_pkcs7_verify(
            $inputFileName,
            $this->getFlags(),
            '/dev/null',
            [],
            $chain
        );

        if(!is_bool($status)) {
            throw new RuntimeException(OpenSSL::getLastError());
        }

        return $status;
    }

}
