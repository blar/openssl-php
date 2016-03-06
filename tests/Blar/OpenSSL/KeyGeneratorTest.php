<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

class KeyGeneratorTest extends TestCase {

    public function testGenerate() {
        $generator = new KeyGenerator();
        $privateKey = $generator->generate();

        $this->assertContains('PRIVATE KEY', (string) $privateKey);
        $this->assertNotContains('PUBLIC KEY', (string) $privateKey);

        $this->assertContains('PUBLIC KEY', (string) $privateKey->getPublicKey());
        $this->assertNotContains('PRIVATE KEY', (string) $privateKey->getPublicKey());
    }

}
