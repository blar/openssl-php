<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

/**
 * Class KeyGeneratorTest
 *
 * @package Blar\OpenSSL
 */
class KeyGeneratorTest extends TestCase {

    public function testGenerate() {
        $generator = new KeyGenerator();
        $privateKey = $generator->generate();

        $this->assertInstanceOf(PrivateKey::class, $privateKey);
        $this->assertContains('PRIVATE KEY', (string) $privateKey);
        $this->assertNotContains('PUBLIC KEY', (string) $privateKey);

        $this->assertInstanceOf(PublicKey::class, $privateKey->getPublicKey());
        $this->assertContains('PUBLIC KEY', (string) $privateKey->getPublicKey());
        $this->assertNotContains('PRIVATE KEY', (string) $privateKey->getPublicKey());
    }

}
