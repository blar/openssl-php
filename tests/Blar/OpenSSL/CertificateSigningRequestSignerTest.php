<?php

/**
 * CertificateSigningRequestSignerTest.php
 *
 * @since 2017-01-01
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

/**
 * Class CertificateSigningRequestSignerTest
 *
 * @package Blar\OpenSSL
 */
class CertificateSigningRequestSignerTest extends TestCase {

    /**
     * Create a new private key for the certificate authority.
     *
     * @return PrivateKey
     */
    public function testCreateCertificateAuthorityPrivateKey(): PrivateKey {
        $generator = new KeyGenerator();
        $privateKey = $generator->generate();

        $this->assertInstanceOf(PrivateKey::class, $privateKey);

        return $privateKey;
    }

    /**
     * Set the subject of the certificate authority.
     *
     * @return Subject
     */
    public function testCreateCertificateAuthoritySubject(): Subject {
        $subject = new Subject();
        $subject['commonName'] = 'My little certificate authority';

        $this->assertInstanceOf(Subject::class, $subject);

        return $subject;
    }

    /**
     * Create a certificate signing request for the certificate authority itself.
     *
     * @depends testCreateCertificateAuthorityPrivateKey
     * @depends testCreateCertificateAuthoritySubject
     */
    public function testCreateCertificateAuthorityCertificateSingingRequest(PrivateKey $privateKey, Subject $subject): CertificateSigningRequest {
        $generator = new CertificateSigningRequestGenerator();
        $generator->setPrivateKey($privateKey);
        $generator->setSubject($subject);
        $csr = $generator->generate();

        $this->assertInstanceOf(CertificateSigningRequest::class, $csr);
        $this->assertTrue($privateKey->getPublicKey()->compareTo($csr->getPublicKey()));

        return $csr;
    }

    /**
     * Self sign the certificate.
     *
     * @depends testCreateCertificateAuthorityCertificateSingingRequest
     * @depends testCreateCertificateAuthorityPrivateKey
     */
    public function testSignCertificateAuthorityCertificateSingingRequest(CertificateSigningRequest $csr, PrivateKey $privateKey): Certificate {
        $signer = new CertificateSigningRequestSigner();
        $signer->setPrivateKey($privateKey);
        $signer->setLifetime(3650);
        $certificate = $signer->selfSign($csr);

        $this->assertInstanceOf(Certificate::class, $certificate);

        return $certificate;
    }

    /**
     * Create a new private key for our first certificate.
     *
     * @return PrivateKey
     */
    public function testCreatePrivateKey(): PrivateKey {
        $generator = new KeyGenerator();
        $privateKey = $generator->generate();
        return $privateKey;
    }

    /**
     * And a subject for the first certificate.
     *
     * @return Subject
     */
    public function testCreateSubject(): Subject {
        $subject = new Subject();
        $subject['commonName'] = 'My first certificate';
        return $subject;
    }

    /**
     * Create a certificate signing request to sign it from the certificate authority.
     *
     * @depends testCreatePrivateKey
     * @depends testCreateSubject
     */
    public function testCreateCertificateSingingRequest(PrivateKey $privateKey, Subject $subject) {
        $generator = new CertificateSigningRequestGenerator();
        $generator->setPrivateKey($privateKey);
        $generator->setSubject($subject);
        $csr = $generator->generate();

        return $csr;
    }

    /**
     * Create a signer for the certificate authority.
     *
     * @depends testCreateCertificateAuthorityPrivateKey
     * @depends testSignCertificateAuthorityCertificateSingingRequest
     */
    public function testCreateSigner(PrivateKey $privateKey, Certificate $certificate) {
        $signer = new CertificateSigningRequestSigner();
        $signer->setPrivateKey($privateKey);
        $signer->setCertificate($certificate);
        $signer->setLifetime(365);

        // the section "usr_cert" set CA:false
        $signer->setExtensions('usr_cert');
        return $signer;
    }

    /**
     * Sign the certificate signing request by the certificate authority.
     *
     * @depends testCreateSigner
     * @depends testCreateCertificateSingingRequest
     */
    public function testSignCertificateSingingRequest(CertificateSigningRequestSigner $signer, CertificateSigningRequest $csr) {
        $certificate = $signer->sign($csr, 1337);

        $this->assertInstanceOf(Certificate::class, $certificate);
        $this->assertEquals(1337, $certificate->getSerial());

        return $certificate;
    }

}
