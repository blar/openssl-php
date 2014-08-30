<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;


use PHPUnit_Framework_TestCase as TestCase;

class SMIMETest extends TestCase {

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

    public function testSign() {
        $certificateSigningRequest = new CertificateSigningRequest($this->getDn());
        $certificate = $certificateSigningRequest->selfSign();

        $headers = array(
            'Subject' => 'foobar',
            'From' => 'wez@example.com',
            'To' => 'gmblar@gmail.com'
        );
        /*
        echo PHP_EOL;
        echo PHP_EOL;
        $message = SMIME::sign("Content-Type: text/plain\r\n\r\nHello World", $certificate, $certificateSigningRequest->getPrivateKey(), $headers);
        echo $message;
        echo PHP_EOL;
        echo PHP_EOL;
        die();
        */
    }

    public function testEncrypt() {
        $certificateSigningRequest = new CertificateSigningRequest($this->getDn());
        $certificate = $certificateSigningRequest->selfSign();

        $headers = array(
            'foo' => 23,
            'bar' => 42,
        );
        /*
        echo PHP_EOL;
        echo PHP_EOL;
        echo $message = SMIME::encrypt('Hello World', $certificate, $headers, PKCS7_TEXT | PKCS7_NOSIGS, OPENSSL_CIPHER_AES_256_CBC);
        echo PHP_EOL;
        echo PHP_EOL;
        var_dump(SMIME::decrypt($message, $certificate, $certificateSigningRequest->getPrivateKey()));
        */
    }
}
