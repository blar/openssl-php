[![License](https://poser.pugx.org/blar/openssl/license)](https://packagist.org/packages/blar/openssl)
[![Latest Stable Version](https://poser.pugx.org/blar/openssl/v/stable)](https://packagist.org/packages/blar/openssl)
[![Build Status](https://travis-ci.org/blar/openssl.svg?branch=master)](https://travis-ci.org/blar/openssl)
[![Coverage Status](https://coveralls.io/repos/github/blar/openssl/badge.svg?branch=master)](https://coveralls.io/github/blar/openssl?branch=master)
[![Dependency Status](https://gemnasium.com/blar/openssl.svg)](https://gemnasium.com/blar/openssl)
[![Flattr](https://button.flattr.com/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=Blar&url=https%3A%2F%2Fgithub.com%2Fblar%2Fopenssl)

# OpenSSL for PHP

## Examples

### Private Key

#### Create a new private key

    $generator = new KeyGenerator();
    $privateKey = $generator->generate();

#### Create a new private key with 2048 bit

    $generator = new KeyGenerator();
    $generator->setBits(2048);
    $privateKey = $generator->generate();

#### Load an existing private key from file

	$privateKey = PrivateKey::loadFromFileName('privatekey.pem');

### Encrypt data with the private key.

    $encrypted = $privateKey->encrypt('Hello World');

### Get public key from private key.

    $publicKey = $privateKey->getPublicKey();

### Decrypt data with the public key

    $publicKey->decrypt($encrypted);
    
## Installation

### Dependencies

[Show dependencies of blar/openssl on gemnasium](https://gemnasium.com/blar/openssl)

### Installation per Composer

    $ composer require blar/openssl

### Installation per Git

    $ git clone https://github.com/blar/openssl.git
