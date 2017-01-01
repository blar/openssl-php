<?php

/**
 * Pkcs12Test.php
 *
 * @since 2016-12-31
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

/**
 * Class Pkcs12Test
 *
 * @package Blar\OpenSSL
 */
class Pkcs12Test extends TestCase {

    public function testCreateUnencrypted() {
        $privateKey = PrivateKey::loadFromFileName(__DIR__ . '/pkcs12/pkcs12_privatekey.pem');
        $certificate = Certificate::createFromFileName(__DIR__ . '/pkcs12/pkcs12_certificate.pem');

        $pkcs12 = new Pkcs12();
        $pkcs12->setPrivateKey($privateKey);
        $pkcs12->setCertificate($certificate);
        $pkcs12->exportToFile(__DIR__ . '/pkcs12.pfx');
    }

    public function testGetPrivateKey() {
        $pkcs12 = Pkcs12::loadFromFileName(__DIR__ . '/pkcs12/pkcs12.pfx');

        $this->assertStringEqualsFile(__DIR__ . '/pkcs12/pkcs12_privatekey.pem', $pkcs12->getPrivateKey());
    }

    public function testGetCertificate() {
        $pkcs12 = Pkcs12::loadFromFileName(__DIR__ . '/pkcs12/pkcs12.pfx');

        $this->assertStringEqualsFile(__DIR__ . '/pkcs12/pkcs12_certificate.pem', $pkcs12->getCertificate());
    }

    public function testCreateEncrypted() {
        $privateKey = PrivateKey::loadFromFileName(__DIR__ . '/pkcs12/pkcs12_privatekey.pem');
        $certificate = Certificate::createFromFileName(__DIR__ . '/pkcs12/pkcs12_certificate.pem');

        $pkcs12 = new Pkcs12();
        $pkcs12->setPrivateKey($privateKey);
        $pkcs12->setCertificate($certificate);
        $pkcs12->exportToFile(__DIR__ . '/pkcs12/pkcs12_encrypted.pfx', 'P7842lFd52X6ri9');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testGetPrivateKeyFromEncryptedWithoutPassword() {
        $pkcs12 = Pkcs12::loadFromFileName(__DIR__ . '/pkcs12/pkcs12_encrypted.pfx');

        $this->assertStringEqualsFile(__DIR__ . '/pkcs12/pkcs12_privatekey.pem', $pkcs12->getPrivateKey());
    }

    public function testGetPrivateKeyFromEncryptedWithPassword() {
        $pkcs12 = Pkcs12::loadFromFileName(__DIR__ . '/pkcs12/pkcs12_encrypted.pfx', 'P7842lFd52X6ri9');

        $this->assertStringEqualsFile(__DIR__ . '/pkcs12/pkcs12_privatekey.pem', $pkcs12->getPrivateKey());
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testGetCertificateFromEncryptedWithoutPassword() {
        $pkcs12 = Pkcs12::loadFromFileName(__DIR__ . '/pkcs12/pkcs12_encrypted.pfx');

        $this->assertStringEqualsFile(__DIR__ . '/pkcs12/pkcs12_privatekey.pem', $pkcs12->getCertificate());
    }

    public function testGetCertificateFromEncryptedWithPassword() {
        $pkcs12 = Pkcs12::loadFromFileName(__DIR__ . '/pkcs12/pkcs12_encrypted.pfx', 'P7842lFd52X6ri9');

        $this->assertStringEqualsFile(__DIR__ . '/pkcs12/pkcs12_certificate.pem', $pkcs12->getCertificate());
    }

}
