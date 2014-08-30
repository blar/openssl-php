<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

class CertificateSigningRequestTest extends TestCase {

    protected function getDn() {
        return array(
            "countryName" => "UK",
            "stateOrProvinceName" => "Somerset",
            "localityName" => "Glastonbury",
            "organizationName" => "The Brain Room Limited",
            "organizationalUnitName" => "PHP Documentation Team",
            "commonName" => "Wez Furlong",
            "emailAddress" => "wez@example.com"
        );
    }

    public function testCreateCertificateSigningRequestWithPrivateKey() {
        # $privateKey = PrivateKey::create();
        # $certificateSigningRequest = new CertificateSigningRequest($this->getDn(), $privateKey);
        # echo $certificateSigningRequest;
    }

    public function testCreateCertificateSigningRequestWithoutPrivateKey() {
        $certificateSigningRequest = new CertificateSigningRequest($this->getDn());
        # echo $certificateSigningRequest;
        # var_dump((string) $certificateSigningRequest->getPrivateKey());
        # var_dump((string) $certificateSigningRequest->getPrivateKey()->getPublicKey());
    }

    public function testSelfSign() {
        $certificateSigningRequest = new CertificateSigningRequest($this->getDn());
        # echo $certificateSigningRequest->getPrivateKey();
        # var_dump($certificateSigningRequest->getPublicKey());

        $certificate = $certificateSigningRequest->selfSign();
        # echo $certificate;
        # var_dump($certificate->getFingerprint('MD5'));
        # var_dump($certificate->getFingerprint('SHA1'));
        # var_dump($certificate->parse());
    }

}
