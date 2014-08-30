<?php

/**
 * @author Andreas Treichel <gmblar+github@gmail.com>
 */

namespace Blar\OpenSSL;

class SMIME {

    public static function sign($message, $certificates, $privateKey, $headers = array(), $flags = PKCS7_DETACHED, $extracerts = NULL) {
        $inputFileName = tempnam(sys_get_temp_dir(), 'smime_unsigned_');
        file_put_contents($inputFileName, $message);

        $outputFileName = tempnam(sys_get_temp_dir(), 'smime_signed_');
        var_dump($outputFileName);
        openssl_pkcs7_sign($inputFileName, $outputFileName, $certificates, $privateKey, $headers, $flags);
        return file_get_contents($outputFileName);
    }

    public static function encrypt($message, $certificates, $headers = array(), $flags = 0, $cipher = OPENSSL_CIPHER_AES_256_CBC) {
        $inputFileName = tempnam(sys_get_temp_dir(), 'smime_decrypted_');
        file_put_contents($inputFileName, $message);

        $outputFileName = tempnam(sys_get_temp_dir(), 'smime_encrypted_');

        openssl_pkcs7_encrypt($inputFileName, $outputFileName, $certificates, $headers, $flags, $cipher);
        return file_get_contents($outputFileName);
    }

    public static function decrypt($message, $certificates, $privateKey = NULL) {
        $inputFileName = tempnam(sys_get_temp_dir(), 'smime_encrypted_');
        file_put_contents($inputFileName, $message);

        $outputFileName = tempnam(sys_get_temp_dir(), 'smime_decrypted_');

        openssl_pkcs7_decrypt($inputFileName, $outputFileName, $certificates, $privateKey);
        return file_get_contents($outputFileName);
    }

}
