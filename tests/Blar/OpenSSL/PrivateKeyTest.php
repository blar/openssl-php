<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use PHPUnit_Framework_TestCase as TestCase;

class PrivateKeyTest extends TestCase {

    public function testCreatePrivateKey1024() {
        /*
        $privateKey = PrivateKey::create(array(
            'private_key_bits' => 1024
        ));
        */
    }

    public function testCreatePrivateKey2048() {
        $privateKey = PrivateKey::create(array(
            'private_key_bits' => 2048
        ));
        var_dump($privateKey->getDetails());
    }

}
