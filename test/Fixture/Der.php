<?php

declare(strict_types=1);

/**
 * Der.php
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

/**
 * Protocol message builder for tests
 *
 * Assembles the RFC 3161 and RFC 6960 structures the codecs validate, so a test
 * can produce a response that matches a request, and vary one field at a time to
 * check that the mismatch is caught.
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
final class Der
{
    public const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

    public const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

    public const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';

    /**
     * Default thisUpdate for an OCSP response and for a CRL.
     *
     * Both readers apply their age bound to thisUpdate whether or not a nextUpdate
     * follows, so the default sits inside that bound at the moment the test suites
     * check against (1_800_000_000), about 28 hours before it.
     */
    public const RECENT_THIS_UPDATE = 1_799_900_000;

    private Asn1 $asn1;

    private Authority $authority;

    public function __construct(?Asn1 $asn1 = null, ?Authority $authority = null)
    {
        $this->asn1 = $asn1 ?? new Asn1();
        $this->authority = $authority ?? Authority::ocsp();
    }

    /**
     * Encode a DER GeneralizedTime.
     */
    public function generalizedTime(int $time): string
    {
        $value = \gmdate('YmdHis', $time) . 'Z';

        return "\x18" . $this->asn1->encodeLength(\strlen($value)) . $value;
    }

    /**
     * Encode a DER ENUMERATED.
     *
     * @param int<0, 255> $value
     */
    public function enumerated(int $value): string
    {
        return "\x0A\x01" . \chr($value);
    }

    /**
     * Encode a DER BIT STRING with no unused bits.
     */
    public function bitString(string $bytes): string
    {
        $value = "\x00" . $bytes;

        return "\x03" . $this->asn1->encodeLength(\strlen($value)) . $value;
    }

    /**
     * Build a TSTInfo body.
     *
     * @param string $imprint    Raw digest the token covers.
     * @param string $hashOid    OID of the digest algorithm.
     * @param string $nonce      DER INTEGER of the nonce, or '' to omit it.
     * @param string $extensions Concatenated DER Extension entries for extensions [1],
     *                           which is IMPLICIT, or '' to omit the field.
     */
    public function tstInfo(
        string $imprint,
        string $hashOid,
        string $nonce = '',
        int $genTime = 1_700_000_000,
        string $extensions = '',
    ): string {
        $messageImprint = $this->asn1->encodeSequence(
            $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($hashOid))
                . $this->asn1->encodeOctetString($imprint),
        );

        return $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->asn1->encodeObjectIdentifier('1.2.3.4.1')
            . $messageImprint
            . $this->asn1->encodeInteger(42)
            . $this->generalizedTime($genTime)
            . $nonce
            . ($extensions === '' ? '' : $this->asn1->encodeContext(1, $extensions)),
        );
    }

    /**
     * Wrap a TSTInfo as a timestamp token (a CMS SignedData ContentInfo).
     *
     * @param list<string> $certsDer Certificates to embed in the token.
     */
    public function timestampToken(string $tstInfo, array $certsDer = []): string
    {
        $encap = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(self::OID_TST_INFO)
                . $this->asn1->encodeContext(0, $this->asn1->encodeOctetString($tstInfo)),
        );

        $certificates = $certsDer === [] ? '' : $this->asn1->encodeContext(0, \implode('', $certsDer));

        $signedData = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(3) . $this->asn1->encodeSet('') . $encap . $certificates
                . $this->asn1->encodeSet(''),
        );

        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(self::OID_SIGNED_DATA) . $this->asn1->encodeContext(0, $signedData),
        );
    }

    /**
     * Wrap a TSTInfo as a timestamp token whose SignerInfo is genuinely signed.
     *
     * The codec verifies the SignerInfo signature and the signed attributes, so a
     * token that is not really signed proves nothing about either. The attributes
     * are the ones RFC 3161 section 2.4.2 requires: content-type, message-digest,
     * and the ESS signing-certificate-v2 naming the TSA certificate.
     *
     * @param list<string>   $extraCertsDer   Certificates to embed besides the signer's.
     * @param Authority|null $signer          Key that signs, or null for the authority itself.
     * @param bool           $embedSignerCert Whether to embed the signer's own certificate,
     *                                        without which the signature cannot be checked.
     * @param bool           $sidByKeyId      Name the signer by subjectKeyIdentifier [0]
     *                                        rather than by issuerAndSerialNumber.
     * @param string|null    $contentTypeOid  Value of the content-type attribute, or null for
     *                                        the id-ct-TSTInfo the encapsulated content claims.
     * @param string|null    $essCertDer      Certificate the signing-certificate-v2 attribute
     *                                        names, or null for the signer's own. '' omits it.
     * @param int<1, max> $signerInfoCount Number of copies of the SignerInfo to emit.
     * @param string|null    $signatureOid    SignerInfo signatureAlgorithm OID, or null for the
     *                                        authority's sha256WithRSAEncryption. RFC 3370
     *                                        section 3.2 admits rsaEncryption here as well.
     */
    public function signedTimestampToken(
        string $tstInfo,
        array $extraCertsDer = [],
        ?Authority $signer = null,
        bool $embedSignerCert = true,
        bool $sidByKeyId = false,
        ?string $contentTypeOid = null,
        ?string $essCertDer = null,
        int $signerInfoCount = 1,
        ?string $signatureOid = null,
    ): string {
        // A token is signed by a TSA certificate: RFC 3161 section 2.3 reserves the
        // key for it, and the codec refuses a token signed by anything else.
        $tsa = $signer ?? Authority::tsa();
        $digestAlgorithm = $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1'));

        $essCert = $essCertDer ?? $tsa->certDer;
        $signedAttrs =
            $this->attribute(
                '1.2.840.113549.1.9.3',
                $this->asn1->encodeObjectIdentifier($contentTypeOid ?? self::OID_TST_INFO),
            )
            . $this->attribute('1.2.840.113549.1.9.4', $this->asn1->encodeOctetString(\hash('sha256', $tstInfo, true)))
            . ($essCert === '' ? '' : $this->signingCertificateV2($essCert));

        $fields = (new Certificate($this->asn1))->fields($tsa->certDer);
        $sid = $sidByKeyId
            ? "\x80" . $this->asn1->encodeLength(20) . $tsa->subjectKeyIdentifier()
            : $this->asn1->encodeSequence($fields['issuer'] . $fields['serial']);

        $signerInfo = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $sid
                . $digestAlgorithm
                . $this->asn1->encodeContext(0, $signedAttrs)
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeObjectIdentifier($signatureOid ?? Authority::SIGNATURE_OID)
                        . $this->asn1->encodeNull(),
                )
                . $this->asn1->encodeOctetString($tsa->sign($this->asn1->encodeSet($signedAttrs))),
        );

        $encap = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(self::OID_TST_INFO)
                . $this->asn1->encodeContext(0, $this->asn1->encodeOctetString($tstInfo)),
        );

        $signedData = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(3)
                . $this->asn1->encodeSet($digestAlgorithm)
                . $encap
                . $this->asn1->encodeContext(0, ($embedSignerCert ? $tsa->certDer : '') . \implode('', $extraCertsDer))
                . $this->asn1->encodeSet(\str_repeat($signerInfo, $signerInfoCount)),
        );

        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(self::OID_SIGNED_DATA) . $this->asn1->encodeContext(0, $signedData),
        );
    }

    /**
     * Encode an ESS signing-certificate-v2 attribute over a certificate.
     *
     * The SHA-256 hashAlgorithm is the ESSCertIDv2 default and so omitted.
     */
    public function signingCertificateV2(string $certDer): string
    {
        return $this->attribute(
            '1.2.840.113549.1.9.16.2.47',
            $this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeOctetString(\hash(
                'sha256',
                $certDer,
                true,
            ))))),
        );
    }

    /**
     * Encode a single CMS Attribute (type plus a one-element value SET).
     */
    public function attribute(string $oid, string $value): string
    {
        return $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($oid) . $this->asn1->encodeSet($value));
    }

    /**
     * Build a complete TimeStampResp around a token.
     *
     * @param int<0, max> $statusCode PKIStatus value.
     */
    public function timestampResponse(int $statusCode, string $tokenDer): string
    {
        return $this->asn1->encodeSequence(
            $this->asn1->encodeSequence($this->asn1->encodeInteger($statusCode)) . $tokenDer,
        );
    }

    /**
     * Build one SingleResponse.
     *
     * @param string   $certId     DER CertID the entry is about.
     * @param string   $status     DER certStatus; defaults to good ([0] IMPLICIT NULL).
     * @param int|null $nextUpdate Unix time of nextUpdate, or null to omit it.
     * @param string   $extensions Concatenated DER Extension entries for singleExtensions [1],
     *                             or '' to omit the field.
     */
    public function singleResponse(
        string $certId,
        string $status = "\x80\x00",
        int $thisUpdate = self::RECENT_THIS_UPDATE,
        ?int $nextUpdate = 1_900_000_000,
        string $extensions = '',
    ): string {
        $next = $nextUpdate === null ? '' : $this->asn1->encodeContext(0, $this->generalizedTime($nextUpdate));
        $single = $extensions === '' ? '' : $this->asn1->encodeContext(1, $this->asn1->encodeSequence($extensions));

        return $this->asn1->encodeSequence($certId . $status . $this->generalizedTime($thisUpdate) . $next . $single);
    }

    /**
     * Build one DER Extension.
     *
     * @param string $oid      Extension type.
     * @param string $value    Extension value octets, wrapped in the OCTET STRING.
     * @param bool   $critical Whether the critical BOOLEAN is emitted as TRUE.
     */
    public function extension(string $oid, string $value = "\x05\x00", bool $critical = false): string
    {
        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier($oid) . ($critical ? $this->asn1->encodeBoolean(true) : '')
                . $this->asn1->encodeOctetString($value),
        );
    }

    /**
     * Build a ResponseData around one or more SingleResponse entries.
     *
     * @param string      $responses   Concatenated SingleResponse entries.
     * @param string|null $responderId DER ResponderID, or null for the authority's own name.
     * @param string      $version     DER version [0] EXPLICIT, or '' to omit it.
     * @param string      $extensions  Concatenated DER Extension entries for
     *                                 responseExtensions [1], or '' to omit the field.
     */
    public function responseData(
        string $responses,
        ?string $responderId = null,
        int $producedAt = 1_700_000_000,
        string $version = '',
        string $extensions = '',
    ): string {
        // RFC 6960 section 4.2.1: responseExtensions is [1] EXPLICIT.
        $responseExtensions = $extensions === ''
            ? ''
            : $this->asn1->encodeContext(1, $this->asn1->encodeSequence($extensions));

        return $this->asn1->encodeSequence(
            $version
            . ($responderId ?? $this->authority->responderIdByName($this->asn1))
            . $this->generalizedTime($producedAt)
            . $this->asn1->encodeSequence($responses)
            . $responseExtensions,
        );
    }

    /**
     * Build a BasicOCSPResponse, genuinely signed by the authority.
     *
     * @param string       $responseData Complete DER ResponseData.
     * @param list<string> $certsDer     Certificates to embed in the certs [0] field.
     * @param Authority|null $signer     Key that signs, or null for the authority itself.
     */
    public function basicResponse(string $responseData, array $certsDer = [], ?Authority $signer = null): string
    {
        $signature = ($signer ?? $this->authority)->sign($responseData);
        $certs = $certsDer === []
            ? ''
            : $this->asn1->encodeContext(0, $this->asn1->encodeSequence(\implode('', $certsDer)));

        return $this->asn1->encodeSequence(
            $responseData
            . $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID) . $this->asn1->encodeNull(),
            )
            . $this->bitString($signature)
            . $certs,
        );
    }

    /**
     * Build a complete, signed OCSPResponse for a CertID.
     *
     * @param string      $certId     DER CertID the response quotes back.
     * @param string      $status     DER certStatus; defaults to good ([0] IMPLICIT NULL).
     * @param int|null    $nextUpdate Unix time of nextUpdate, or null to omit it.
     */
    public function ocspResponse(
        string $certId,
        string $status = "\x80\x00",
        int $thisUpdate = self::RECENT_THIS_UPDATE,
        ?int $nextUpdate = 1_900_000_000,
    ): string {
        return $this->ocspResponseBytes(
            0,
            $this->basicResponse($this->responseData($this->singleResponse(
                $certId,
                $status,
                $thisUpdate,
                $nextUpdate,
            ))),
        );
    }

    /**
     * Build a CertificateList, genuinely signed by the authority.
     *
     * @param int|null $nextUpdate Unix time of nextUpdate, or null to omit it.
     * @param string|null $issuer  DER issuer Name, or null for the authority's own subject.
     */
    public function crl(
        int $thisUpdate = self::RECENT_THIS_UPDATE,
        ?int $nextUpdate = 1_900_000_000,
        ?string $issuer = null,
        ?Authority $signer = null,
    ): string {
        $algorithmId = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID) . $this->asn1->encodeNull(),
        );

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $algorithmId
            . ($issuer ?? $this->authority->subject($this->asn1))
            . $this->generalizedTime($thisUpdate)
            . ($nextUpdate === null ? '' : $this->generalizedTime($nextUpdate)),
        );

        return $this->asn1->encodeSequence(
            $tbs . $algorithmId . $this->bitString(($signer ?? $this->authority)->sign($tbs)),
        );
    }

    /**
     * Build an OCSPResponse with the given status and optional basic response.
     *
     * @param int<0, 255> $status OCSPResponseStatus value.
     * @param string|null $basic  DER BasicOCSPResponse, or null to omit responseBytes.
     */
    public function ocspResponseBytes(int $status, ?string $basic): string
    {
        $bytes = $basic === null
            ? ''
            : $this->asn1->encodeContext(
                0,
                $this->asn1->encodeSequence(
                    $this->asn1->encodeObjectIdentifier(self::OID_OCSP_BASIC) . $this->asn1->encodeOctetString($basic),
                ),
            );

        return $this->asn1->encodeSequence($this->enumerated($status) . $bytes);
    }
}
