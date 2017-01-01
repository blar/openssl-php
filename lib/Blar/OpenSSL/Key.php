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
    protected static function isKeyResource($resource): bool {
        if(!is_resource($resource)) {
            return FALSE;
        }
        if(get_resource_type($resource) != 'OpenSSL key') {
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Key constructor.
     *
     * @param $handle
     */
    public function __construct($handle) {
        $this->setHandle($handle);
    }

    public function __destruct() {
        if(static::isKeyResource($this->handle)) {
            openssl_pkey_free($this->handle);
        }
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

    /**
     * @return array
     */
    public function getDetails(): array {
        return openssl_pkey_get_details($this->getHandle());
    }

}
