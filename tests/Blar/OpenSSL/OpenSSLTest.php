<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

class OpenSSLTest extends TestCase {

    public function testRandomBytes() {
        $values = [];
        for($i = 0; $i < 10; $i++) {
            $values[] = OpenSSL::getPseudoRandomBytes(8);
        }
        foreach(array_count_values($values) as $count) {
            $this->assertSame(1, $count);
        }
    }

    public function testGetCipherMethods() {
        $cipherMethods = OpenSSL::getCipherMethods();
        $this->assertTrue(is_array($cipherMethods));
    }

    public function testGetDigestMethods() {
        $digestMethods = OpenSSL::getDigestMethods();
        $this->assertTrue(is_array($digestMethods));
    }

    public function testGetCertificateLocations() {
        $certificateLocations = OpenSSL::getCertificateLocations();
        $this->assertTrue(is_array($certificateLocations));
    }

}
