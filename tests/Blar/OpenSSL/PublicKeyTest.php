<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

/**
 * Class PublicKeyTest
 *
 * @package Blar\OpenSSL
 */
class PublicKeyTest extends TestCase {

    public function testEncryptAndDecrypt() {
        $generator = new KeyGenerator();

        $privateKey = $generator->generate();
        $publicKey = $privateKey->getPublicKey();

        $encrypted = $publicKey->encrypt('foobar');
        $this->assertNotSame('foobar', $encrypted);

        $decrypted = $privateKey->decrypt($encrypted);
        $this->assertSame('foobar', $decrypted);
    }

}
