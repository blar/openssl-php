<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use DateTime;
use PHPUnit_Framework_TestCase as TestCase;

class CertificateTest extends TestCase {

    public function testValidFrom() {
        $certificate = Certificate::createFromFileName(__DIR__.'/certificates/google.pem');

        $validFrom = new DateTime('@1481808840');
        $this->assertEquals($validFrom, $certificate->getValidFrom());
    }

    public function testValidUntil() {
        $certificate = Certificate::createFromFileName(__DIR__.'/certificates/google.pem');

        $validUntil = new DateTime('@1489066440');
        $this->assertEquals($validUntil, $certificate->getValidUntil());
    }

    public function testSubjectAltName() {
        $certificate = Certificate::createFromFileName(__DIR__.'/certificates/google.pem');

        $this->assertTrue($certificate->hasExtension('subjectAltName'));
        $this->assertSame('DNS:www.google.de', $certificate->getExtension('subjectAltName'));
    }

    public function testCheckPurpose() {
        $certificate = Certificate::createFromFileName(__DIR__.'/certificates/google.pem');

        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_CRL_SIGN));
        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_SSL_SERVER));
        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_SMIME_SIGN));
        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_SMIME_ENCRYPT));
    }

    public function testFingerprint() {
        $certificate = Certificate::createFromFileName(__DIR__.'/certificates/google.pem');

        $this->assertEquals('61a17e36d74d00b0bd42f366476697456f28f798', $certificate->getFingerprint()->getHexValue());
    }

    public function testGetPublicKey() {
        $certificate = Certificate::createFromFileName(__DIR__.'/certificates/google.pem');
        $publicKey = $certificate->getPublicKey();

        $this->assertInstanceOf(PublicKey::class, $publicKey);
    }

}
