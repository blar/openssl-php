<?php

/**
 * CertificateSigningRequestGeneratorTest.php
 *
 * @since 2016-12-31
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

class CertificateSigningRequestGeneratorTest extends TestCase {

    protected function generatePrivateKey(): PrivateKey {
        $generator = new KeyGenerator();
        $generator->setType(OPENSSL_KEYTYPE_RSA);
        $generator->setBits(2048);
        $generator->setDigestAlgorithm('SHA1');
        return $generator->generate();
    }

    protected function getSubject(): Subject {
        $subject = new Subject();
        $subject['commonName'] = 'example.com';
        return $subject;
    }

    public function testGenerate() {
        $privateKey = $this->generatePrivateKey();
        $publicKey = $privateKey->getPublicKey();

        $generator = new CertificateSigningRequestGenerator();
        $generator->setPrivateKey($privateKey);
        $generator->setSubject($this->getSubject());

        $csr = $generator->generate();

        $this->assertInstanceOf(CertificateSigningRequest::class, $csr);
        $this->assertSame('example.com', $csr->getSubject()['commonName']);
        $this->assertTrue($publicKey->compareTo($csr->getPublicKey()));
    }

    public function testGenerateWithSubjectAltName() {
        $privateKey = $this->generatePrivateKey();
        $publicKey = $privateKey->getPublicKey();

        $generator = new CertificateSigningRequestGenerator();
        $generator->setPrivateKey($privateKey);
        $generator->setSubject($this->getSubject());
        $generator->setSubjectAltNames([
            'DNS:foo.example.com',
            'DNS:bar.example.com'
        ]);

        $csr = $generator->generate();

        $this->assertInstanceOf(CertificateSigningRequest::class, $csr);
        $this->assertSame('example.com', $csr->getSubject()['commonName']);
        $this->assertGreaterThan(0, strpos($csr->export(true), 'X509v3 Subject Alternative Name'));
        $this->assertGreaterThan(0, strpos($csr->export(true), 'DNS:foo.example.com, DNS:bar.example.com'));
        $this->assertTrue($publicKey->compareTo($csr->getPublicKey()));
    }

}
