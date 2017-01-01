<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

/**
 * Class PrivateKeyTest
 *
 * @package Blar\OpenSSL
 */
class PrivateKeyTest extends TestCase {

    public function testKey1024Bits() {
        $generator = new KeyGenerator();
        $generator->setBits(1024);

        $privateKey = $generator->generate();
        $this->assertSame(1024, $privateKey->getBits());
    }

    public function testKey2048Bits() {
        $generator = new KeyGenerator();
        $generator->setBits(2048);

        $privateKey = $generator->generate();
        $this->assertSame(2048, $privateKey->getBits());
    }

    public function testEncryptAndDecrypt() {
        $generator = new KeyGenerator();
        $privateKey = $generator->generate();

        $encrypted = $privateKey->encrypt('foobar');
        $this->assertNotSame('foobar', $encrypted);

        $publicKey = $privateKey->getPublicKey();
        $decrypted = $publicKey->decrypt($encrypted);
        $this->assertSame('foobar', $decrypted);
    }

}
