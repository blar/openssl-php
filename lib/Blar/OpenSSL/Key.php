<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use RuntimeException;

/**
 * Class Key
 *
 * @package Blar\OpenSSL
 */
abstract class Key {

    /**
     * @var resource
     */
    private $handle;

    /**
     * @param mixed $resource
     *
     * @return bool
     */
    protected static function isKeyResource($resource) {
        if(!is_resource($resource)) {
            return FALSE;
        }
        if(get_resource_type($resource) != 'OpenSSL key') {
            return FALSE;
        }
        return TRUE;
    }

    /**
     * @param string $key
     * @param string $password
     */
    public function __construct($key, string $password = NULL) {
        $this->load($key, $password);
    }

    /**
     * @param mixed $key
     */
    public function load($key) {
        if(self::isKeyResource($key)) {
            $this->setHandle($key);
        }
    }

    public function __destruct() {
        if(!is_resource($this->handle)) {
            return;
        }
        openssl_pkey_free($this->handle);
    }

    /**
     * @return array
     */
    public function getDetails() {
        $details = openssl_pkey_get_details($this->getHandle());
        /* Die Details enthalten Steuerzeichen, darum erst einmal nicht druckbare Zeichen per base64_encode verarbeiten. */
        /*
        array_walk_recursive($details, function (&$data) {
            if(!ctype_print($data)) {
                $data = base64_encode($data);
            }
        });
        */
        return $details;
    }

    /**
     * @return resource
     */
    public function getHandle() {
        return $this->handle;
    }

    /**
     * @param resource $handle
     */
    public function setHandle($handle) {
        if(!self::isKeyResource($handle)) {
            throw new RuntimeException('Handle is not a Private key resource');
        }
        $this->handle = $handle;
    }

}
