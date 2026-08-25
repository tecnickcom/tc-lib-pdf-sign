<?php

declare(strict_types=1);

/**
 * Credentials.php
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 *
 * This file is part of tc-lib-pdf-sign software library.
 */

namespace Test\Fixture;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;

/**
 * Test key and certificate generator
 *
 * Generates the self-signed credentials the signing tests need. Key generation
 * dominates their runtime, so results are memoised per key type and curve for
 * the lifetime of the process.
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
final class Credentials
{
    /**
     * Generated credentials, keyed by type, curve, and common name.
     *
     * @var array<string, array{key: OpenSSLAsymmetricKey, cert_pem: string, cert_der: string}|null>
     */
    private static array $cache = [];

    /**
     * Generate a self-signed credential.
     *
     * @param string $keyType   One of rsa, ec, dsa.
     * @param string $curve     Curve name for an EC key.
     * @param string $commonName Subject common name, to vary the issuer between chains.
     *
     * @return array{key: OpenSSLAsymmetricKey, cert_pem: string, cert_der: string}|null
     *         Null when the platform cannot generate this key type.
     */
    public static function make(
        string $keyType = 'rsa',
        string $curve = 'prime256v1',
        string $commonName = 'tc-lib-pdf-sign signer',
    ): ?array {
        $cacheKey = $keyType . '|' . $curve . '|' . $commonName;
        if (\array_key_exists($cacheKey, self::$cache)) {
            return self::$cache[$cacheKey];
        }

        self::$cache[$cacheKey] = self::generate($keyType, $curve, $commonName);

        return self::$cache[$cacheKey];
    }

    /**
     * @return array{key: OpenSSLAsymmetricKey, cert_pem: string, cert_der: string}|null
     */
    private static function generate(string $keyType, string $curve, string $commonName): ?array
    {
        $config = [
            'config' => __DIR__ . '/../../openssl.cnf',
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        if ($keyType === 'ec') {
            $config['private_key_type'] = OPENSSL_KEYTYPE_EC;
            $config['curve_name'] = $curve;
        } elseif ($keyType === 'dsa') {
            $config['private_key_type'] = OPENSSL_KEYTYPE_DSA;
            $config['private_key_bits'] = 1024;
        }

        $key = \openssl_pkey_new($config);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            return null;
        }

        $csr = \openssl_csr_new(['commonName' => $commonName], $key, $config);
        if (!$csr instanceof OpenSSLCertificateSigningRequest) {
            return null;
        }

        $cert = \openssl_csr_sign($csr, null, $key, 365, $config);
        if (!$cert instanceof OpenSSLCertificate) {
            return null;
        }

        $certPem = '';
        \openssl_x509_export($cert, $certPem);

        return ['key' => $key, 'cert_pem' => $certPem, 'cert_der' => self::pemToDer($certPem)];
    }

    /**
     * Decode a PEM certificate to DER.
     */
    public static function pemToDer(string $pem): string
    {
        $stripped = (string) \preg_replace('/-----[^-]+-----|\s+/', '', $pem);

        return (string) \base64_decode($stripped, true);
    }
}
