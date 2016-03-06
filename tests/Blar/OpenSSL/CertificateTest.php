<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;
use SplFileInfo;

class CertificateTest extends TestCase {

    protected function loadCertificate() {
        $file = new SplFileInfo(__DIR__ . '/test.pem');
        $certificate = new Certificate($file);

        return $certificate;
    }

    public function testIsPemOrDerFormat() {
        $certificate = $this->loadCertificate();
        $this->assertTrue(Certificate::isDerFormat($certificate));
        $this->assertFalse(Certificate::isPemFormat($certificate));
    }

    public function testCheckPurpose() {
        $certificate = $this->loadCertificate();

        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_CRL_SIGN));
        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_SSL_SERVER));
        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_SMIME_SIGN));
        $this->assertFalse($certificate->checkPurpose(X509_PURPOSE_SMIME_ENCRYPT));
    }

    public function testFingerprint() {
        $certificate = $this->loadCertificate();
        $this->assertEquals(
            '18a5dc7965fe18a4767c8f2d36199cefcdda7c56',
            $certificate->getFingerprint()
        );
    }

    public function testDerFormattedCertificate() {
        $certificate = $this->loadCertificate();
        $info = $certificate->getInfo(true);

        $this->assertSame('DE', $info['subject']['countryName']);
        $this->assertSame('Foobox', $info['subject']['organizationName']);
        $this->assertSame('Development', $info['subject']['organizationalUnitName']);
        $this->assertSame('example', $info['subject']['commonName']);
    }

    public function testGetPublicKey() {
        $certificate = $this->loadCertificate();

        $this->assertContains('PUBLIC KEY', (string) $certificate->getPublicKey());
    }

}
