<?php

/**
 * CertificateSigningRequestGenerator.php
 *
 * @since 2016-12-31
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

/**
 * Class CertificateSigningRequestGenerator
 *
 * @package Blar\OpenSSL
 */
class CertificateSigningRequestGenerator {

    /**
     * @var PrivateKey
     */
    private $privateKey;

    /**
     * @var Subject
     */
    private $subject;

    /**
     * @var array
     */
    private $subjectAltNames = [];

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
     * @return array
     */
    public function getSubjectAltNames(): array {
        return $this->subjectAltNames;
    }

    /**
     * Prefixes for entries: "email", "URI", "DNS", "IP", "RID", "otherName"
     *
     * @param array $subjectAltNames
     */
    public function setSubjectAltNames(array $subjectAltNames) {
        $this->subjectAltNames = $subjectAltNames;
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
            $options['req_extensions'] = $this->getExtensions();
        }
        if($this->getConfigFileName()) {
            $options['config'] = $this->getConfigFileName();
        }
        return $options;
    }

    /**
     * @return CertificateSigningRequest
     */
    public function generate(): CertificateSigningRequest {
        if($this->getSubjectAltNames()) {
            $tempFileName = $this->getTemporaryFileName();
            $this->writeCustomConfigFile($tempFileName, $this->getSubjectAltNames());
            $this->setConfigFileName($tempFileName);
            $this->setExtensions('req_extensions');
        }
        $privateKey = $this->getPrivateKey();
        $handle = openssl_csr_new(
            $this->getSubject()->getArrayCopy(),
            $privateKey,
            $this->getOptions()
        );
        return new CertificateSigningRequest($handle);
    }

    protected function getTemporaryFileName(): string {
        return tempnam(sys_get_temp_dir(), 'openssl_');
    }

    /**
     * The subjectAltName can only be defined in the openssl config. So we need a temporary config file.
     *
     * @param string $fileName
     * @param array $subjectAltNames
     */
    protected function writeCustomConfigFile(string $fileName, array $subjectAltNames) {
        $content = implode(PHP_EOL, [
            '[req]',
            'prompt = no',
            'string_mask = utf8only',
            'distinguished_name = req_distinguished_name',
            '[req_distinguished_name]',
            '[req_extensions]',
            'subjectAltName = '.implode(',', $subjectAltNames)
        ]);
        file_put_contents($fileName, $content);
    }

}
