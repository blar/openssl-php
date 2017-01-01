<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

class CertificateSigningRequestTest extends TestCase {

    public function testSubject() {
        $csr = new CertificateSigningRequest('file://'.__DIR__.'/test.csr');
        $this->assertSame('example.com', $csr->getSubject()['commonName']);
    }

}
