<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

class CertificateSigningRequestTest extends TestCase {

    protected function generatePrivateKey() {
        $generator = new KeyGenerator();
        $generator->setType(OPENSSL_KEYTYPE_RSA);
        $generator->setBits(4096);
        $generator->setDigestAlgorithm('SHA1');
        return $generator->generate();
    }

    protected function getSubject() {
        $subject = new Subject();
        $subject->countryName = 'UK';
        $subject->stateOrProvinceName = 'Somerset';
        $subject->localityName = 'Glastonbury';
        $subject->organizationName = 'The Brain Room Limited';
        $subject->organizationalUnitName = 'PHP Documentation Team';
        $subject->commonName = 'Wez Furlong';
        $subject->emailAddress = 'wez@example.com';
        return $subject;
    }

    public function testCreateCertificateSigningRequestWithPrivateKey() {
        $privateKey = $this->generatePrivateKey();

        $certificateSigningRequest = new CertificateSigningRequest();
        $certificateSigningRequest->setPrivateKey($privateKey);
        $certificateSigningRequest->setSubject($this->getSubject());
    }

    public function testCreateCertificateSigningRequestWithoutPrivateKey() {
        $certificateSigningRequest = new CertificateSigningRequest();
        $certificateSigningRequest->setSubject($this->getSubject());
    }

    public function testSelfSign() {
        $privateKey = $this->generatePrivateKey();

        $certificateSigningRequest = new CertificateSigningRequest();
        $certificateSigningRequest->setPrivateKey($privateKey);
        $certificateSigningRequest->setSubject($this->getSubject());
        $certificateSigningRequest->generate();
        $certificateSigningRequest->selfSign();
    }

}
