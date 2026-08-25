<?php

declare(strict_types=1);

/**
 * Authority.php
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

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * Signing authority backed by a committed test key pair
 *
 * The OCSP and CRL codecs verify the signature over what they are given, so the
 * fixtures are signed by one of the key pairs in test/data. See
 * test/data/generate.sh.
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
final class Authority
{
    /**
     * sha256WithRSAEncryption, the algorithm every fixture key uses.
     */
    public const SIGNATURE_OID = '1.2.840.113549.1.1.11';

    /**
     * Loaded authorities, keyed by file name.
     *
     * @var array<string, self>
     */
    private static array $cache = [];

    private function __construct(
        public readonly string $certPem,
        public readonly string $certDer,
        private readonly OpenSSLAsymmetricKey $key,
    ) {}

    /**
     * The self-signed CA of the chain that carries no AIA or CRL extensions.
     */
    public static function ocsp(): self
    {
        return self::load('ocsp_ca');
    }

    /**
     * The self-signed CA of the chain that carries AIA and CRL extensions.
     */
    public static function ltv(): self
    {
        return self::load('ltv_ca');
    }

    /**
     * The leaf of the ltv CA, the one fixture certificate carrying AIA and CRL
     * distribution points.
     */
    public static function ltvLeaf(): self
    {
        return self::load('ltv_cert');
    }

    /**
     * A responder the ocsp CA delegated to, carrying id-kp-OCSPSigning.
     */
    public static function responder(): self
    {
        return self::load('ocsp_responder');
    }

    /**
     * A second responder of the ocsp CA, with the same subject Name as responder().
     *
     * What an authority that has rolled its responder key holds: two certificates
     * the ResponderID names equally, both authorised, and only one of them the key
     * that signed a given response.
     */
    public static function rolledResponder(): self
    {
        return self::load('ocsp_rolled_responder');
    }

    /**
     * A leaf certificate with no OCSPSigning purpose, for the negative case.
     */
    public static function leaf(): self
    {
        return self::load('ocsp_leaf');
    }

    /**
     * A leaf carrying no subjectKeyIdentifier extension.
     *
     * RFC 5280 section 4.2.1.2 only recommends the extension, so a SignerIdentifier
     * naming its signer by key id has to be resolved against a bag that may hold a
     * certificate answering to no key id at all.
     */
    public static function noKeyId(): self
    {
        return self::load('ocsp_no_keyid');
    }

    /**
     * A delegated responder whose certificate expired in 2021.
     */
    public static function expiredResponder(): self
    {
        return self::load('ocsp_expired_responder');
    }

    /**
     * A TSA of the ocsp CA, carrying id-kp-timeStamping and valid 2020-2040.
     */
    public static function tsa(): self
    {
        return self::load('ocsp_tsa');
    }

    /**
     * A TSA carrying id-kp-timeStamping without the critical flag.
     *
     * RFC 3161 section 2.3 requires the extension to be critical as well as
     * present.
     */
    public static function laxTsa(): self
    {
        return self::load('ocsp_lax_tsa');
    }

    /**
     * A TSA whose certificate expired in 2021.
     */
    public static function expiredTsa(): self
    {
        return self::load('ocsp_expired_tsa');
    }

    /**
     * A delegated responder carrying id-kp-OCSPSigning whose critical keyUsage
     * admits keyEncipherment alone.
     *
     * RFC 5280 section 4.2.1.3 reserves digitalSignature for a signature that is not
     * over a certificate or a CRL. The purpose says what the key is for, the key
     * usage whether it may sign at all.
     */
    public static function unsigningResponder(): self
    {
        return self::load('ocsp_unsigning_responder');
    }

    /**
     * A TSA carrying a critical id-kp-timeStamping whose critical keyUsage admits
     * keyEncipherment alone, for the same rule as unsigningResponder().
     */
    public static function unsigningTsa(): self
    {
        return self::load('ocsp_unsigning_tsa');
    }

    /**
     * Sign bytes with this authority's key, as sha256WithRSAEncryption by default.
     *
     * @param int $opensslAlgo Digest constant, for a fixture that has to carry a
     *                         signature the codecs hold to their SHA-1 opt-in.
     */
    public function sign(string $data, int $opensslAlgo = OPENSSL_ALGO_SHA256): string
    {
        $signature = '';
        if (!\openssl_sign($data, $signature, $this->key, $opensslAlgo)) {
            throw new RuntimeException('Unable to sign the fixture');
        }

        return $signature;
    }

    /**
     * The subject Name of this authority, as the certificate encodes it.
     */
    public function subject(Asn1 $asn1): string
    {
        return (new Certificate($asn1))->fields($this->certDer)['subject'];
    }

    /**
     * The raw subjectKeyIdentifier extension value of this authority.
     */
    public function subjectKeyIdentifier(): string
    {
        $info = \openssl_x509_parse($this->certPem);
        if (!\is_array($info)) {
            throw new RuntimeException('Unable to parse the fixture certificate');
        }

        /** @var mixed $identifier */
        $identifier = $info['extensions']['subjectKeyIdentifier'] ?? '';
        if (!\is_string($identifier)) {
            throw new RuntimeException('The fixture certificate carries no subjectKeyIdentifier');
        }

        return (string) \hex2bin(\str_replace(':', '', $identifier));
    }

    /**
     * ResponderID ::= byName [1] EXPLICIT Name.
     */
    public function responderIdByName(Asn1 $asn1): string
    {
        return $asn1->encodeContext(1, $this->subject($asn1));
    }

    /**
     * ResponderID ::= byKey [2] EXPLICIT KeyHash, the SHA-1 of the public key.
     */
    public function responderIdByKey(Asn1 $asn1): string
    {
        $publicKey = (new Certificate($asn1))->fields($this->certDer)['public_key'];

        return $asn1->encodeContext(2, $asn1->encodeOctetString(\hash('sha1', $publicKey, true)));
    }

    private static function load(string $name): self
    {
        if (isset(self::$cache[$name])) {
            return self::$cache[$name];
        }

        $certPem = (string) \file_get_contents(__DIR__ . '/../data/' . $name . '.pem');
        $key = \openssl_pkey_get_private((string) \file_get_contents(__DIR__ . '/../data/' . $name . '.key'));
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Unable to load the fixture key: ' . $name);
        }

        self::$cache[$name] = new self($certPem, Certificate::pemToDer($certPem), $key);

        return self::$cache[$name];
    }
}
