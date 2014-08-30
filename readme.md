[![Build Status](https://travis-ci.org/blar/openssl.png?branch=master)](https://travis-ci.org/blar/openssl)
[![Coverage Status](https://coveralls.io/repos/blar/openssl/badge.png?branch=master)](https://coveralls.io/r/blar/openssl?branch=master)
[![Dependency Status](https://gemnasium.com/blar/openssl.svg)](https://gemnasium.com/blar/openssl)
[![Dependencies Status](https://depending.in/blar/openssl.png)](http://depending.in/blar/openssl)

# OpenSSL für PHP

## Private Key

Einen Private Key mit den Grundeinstellungen aus der OpenSSL-Konfiguration (openssl.cnf) erstellen:

    $privateKey = PrivateKey::create();

Einen Private Key mit einer anderen Schlüssellänge erstellen:

    $privateKey = PrivateKey::create(array(
        'private_key_bits' => 2048
    ));

## Public Key

Den Public Key aus dem Private Key extrahieren:

    $publicKey = $privateKey->getPublicKey();
