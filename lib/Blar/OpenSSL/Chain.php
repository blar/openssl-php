<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

use ArrayObject;
use Blar\Filesystem\TempFile;

/**
 * Class Chain
 *
 * @package Blar\OpenSSL
 */
class Chain extends ArrayObject {

    /**
     * @return string
     */
    public function __toString(): string {
        return implode("\n", $this->getArrayCopy());
    }

    /**
     * Verify the chain file.
     *
     * @param int $purpose X509_PURPOSE_*
     *
     * @return bool
     */
    public function verify(int $purpose = X509_PURPOSE_ANY): bool {
        $chainFile = new TempFile();
        $chainFile->setContent($this);

        $certificate = $this[0];
        return $certificate->checkPurpose($purpose, [], $chainFile);
    }

}
