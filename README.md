[![License](https://poser.pugx.org/blar/openssl/license)](https://packagist.org/packages/blar/openssl)
[![Latest Stable Version](https://poser.pugx.org/blar/openssl/v/stable)](https://packagist.org/packages/blar/openssl)
[![Build Status](https://travis-ci.org/blar/openssl.svg?branch=master)](https://travis-ci.org/blar/openssl)
[![Coverage Status](https://coveralls.io/repos/github/blar/openssl/badge.svg?branch=master)](https://coveralls.io/github/blar/openssl?branch=master)
[![Dependency Status](https://gemnasium.com/blar/openssl.svg)](https://gemnasium.com/blar/openssl)
[![Flattr](https://button.flattr.com/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=Blar&url=https%3A%2F%2Fgithub.com%2Fblar%2Fopenssl)

# OpenSSL für PHP

## Beispiele

### Private Key

Einen Private Key mit den Grundeinstellungen aus der OpenSSL-Konfiguration (openssl.cnf) erstellen:

    $generator = new KeyGenerator();
    $privateKey = $generator->generate();

Einen Private Key mit einer anderen Schlüssellänge erstellen:

    $generator = new KeyGenerator();
    $generator->setBits(2048);
    $privateKey = $generator->generate();

### Verschlüsseln mit dem Private Key

    $encrypted = $privateKey->crypt('Hello World');

### Public Key aus dem Private Key extrahieren

    $publicKey = $privateKey->getPublicKey();

### Entschlüsseln mit dem Public Key

    $publicKey->decrypt($encrypted);

### Certificate Signing Request

    $csr = new CertificateSigningRequest();
    $csr->setPrivateKey($privateKey);
    
### SMIME mit Zertifikat und Private Key

    $pkcs7 = new Pkcs7();
    $pkcs7->setCertificate($certificate);
    $pkcs7->setPrivateKey($privateKey);
    
    $smime = $pkcs7->sign($message);

### Mit PKCS12

    $pkcs12 = new Pkcs12();

    $pkcs7 = new Pkcs7();
    // Setzt Zertifikat und Private Key.
    $pkcs7->setPkcs12($pkcs12);
    
    $smime = $pkcs7->sign($message);
    

## Installation

### Abhängigkeiten

[Abhängigkeiten von blar/openssl auf gemnasium anzeigen](https://gemnasium.com/blar/openssl)

### Installation per Composer

    $ composer require blar/openssl

### Installation per Git

    $ git clone https://github.com/blar/openssl.git
