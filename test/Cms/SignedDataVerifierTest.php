<?php

declare(strict_types=1);

/**
 * SignedDataVerifierTest.php
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

namespace Test\Cms;

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Builder;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Cms\SignatureVerifier;
use Com\Tecnick\Pdf\Sign\Cms\SignedDataVerifier;
use Com\Tecnick\Pdf\Sign\Exception;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Der;

/**
 * CMS SignedDataVerifier Test
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(SignedDataVerifier::class)]
final class SignedDataVerifierTest extends TestCase
{
    private Asn1 $asn1;

    private Der $der;

    private SignedDataVerifier $verifier;

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->der = new Der($this->asn1);
        $this->verifier = new SignedDataVerifier($this->asn1);
    }

    /**
     * A signed timestamp token over an arbitrary TSTInfo.
     */
    private function token(?Authority $signer = null): string
    {
        return $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            [],
            $signer,
        );
    }

    public function testVerifyAcceptsAGenuineToken(): void
    {
        $this->verifier->verify($this->token());
        $this->expectNotToPerformAssertions();
    }

    /**
     * SignedData heads that RFC 5652 section 5.1 does not shape that way.
     *
     * @return array<string, array{callable(Asn1): string, callable(Asn1): string}>
     */
    public static function malformedSignedDataHeadProvider(): array
    {
        return [
            'version is an OCTET STRING' => [
                static fn(Asn1 $asn1): string => $asn1->encodeOctetString("\x03"),
                static fn(Asn1 $asn1): string => $asn1->encodeSet(''),
            ],
            'version is not minimally encoded' => [
                static fn(Asn1 $_asn1): string => "\x02\x02\x00\x03",
                static fn(Asn1 $asn1): string => $asn1->encodeSet(''),
            ],
            'digestAlgorithms is not a SET' => [
                static fn(Asn1 $asn1): string => $asn1->encodeInteger(3),
                static fn(Asn1 $asn1): string => $asn1->encodeOctetString(\str_repeat('P', 64)),
            ],
            'digestAlgorithms holds something else' => [
                static fn(Asn1 $asn1): string => $asn1->encodeInteger(3),
                static fn(Asn1 $asn1): string => $asn1->encodeSet($asn1->encodeOctetString('x')),
            ],
        ];
    }

    /**
     * @param callable(Asn1): string $version
     * @param callable(Asn1): string $digestAlgorithms
     */
    #[DataProvider('malformedSignedDataHeadProvider')]
    public function testVerifyHoldsTheSignedDataHeadToItsShape(callable $version, callable $digestAlgorithms): void
    {
        // The two fields ahead of encapContentInfo are held to the shape RFC 5652
        // section 5.1 gives them, as the SignerInfo version two levels down is.
        // OpenSSL decodes none of these.
        $token = $this->tokenWithHead($version($this->asn1), $digestAlgorithms($this->asn1));

        $this->expectException(Exception::class);
        $this->verifier->verify($token);
    }

    /**
     * The genuine token with its SignedData version and digestAlgorithms replaced.
     */
    private function tokenWithHead(string $version, string $digestAlgorithms): string
    {
        $token = $this->token();

        $offset = 0;
        $root = $this->asn1->readTlv($token, $offset);

        $rootOffset = 0;
        $type = $this->asn1->readTlv($root['value'], $rootOffset);
        $content = $this->asn1->readTlv($root['value'], $rootOffset);

        $contentOffset = 0;
        $signedData = $this->asn1->readTlv($content['value'], $contentOffset);

        $headOffset = 0;
        $this->asn1->readTlv($signedData['value'], $headOffset);
        $this->asn1->readTlv($signedData['value'], $headOffset);

        return $this->asn1->encodeSequence(
            $type['raw']
                . $this->asn1->encodeContext(
                    0,
                    $this->asn1->encodeSequence(
                        $version . $digestAlgorithms . \substr($signedData['value'], $headOffset),
                    ),
                ),
        );
    }

    public function testVerifyTriesEveryCertificateTheSignerIdentifierNames(): void
    {
        // The CertificateSet is covered by no signature, so every candidate carrying
        // the SignerIdentifier is tried rather than only the first.
        $tsa = Authority::tsa();
        $fields = (new Certificate($this->asn1))->fields($tsa->certDer);
        $decoy = $this->certificateNamed($fields['issuer'], $fields['serial']);

        // The decoy is embedded ahead of the signer's own certificate.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            [$decoy, $tsa->certDer],
            null,
            false,
        );

        $this->assertSame($tsa->certDer, $this->verifier->verify($token));
    }

    /**
     * A parseable certificate carrying a given issuer Name and serial, and nothing
     * else that belongs to the certificate they came from.
     */
    private function certificateNamed(string $issuerRaw, string $serialRaw): string
    {
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeContext(0, $this->asn1->encodeInteger(2))
                . $serialRaw
                . $this->asn1->encodeSequence('')
                . $issuerRaw
                . $this->asn1->encodeSequence("\x18\x0F20200101000000Z\x18\x0F20400101000000Z")
                . $this->asn1->encodeSequence('')
                . $this->asn1->encodeSequence($this->asn1->encodeSequence('') . "\x03\x02\x00\x01"),
        );

        return $this->asn1->encodeSequence($tbs . $this->asn1->encodeSequence('') . "\x03\x02\x00\x01");
    }

    public function testVerifyAcceptsATokenIdentifiedByRsaEncryption(): void
    {
        // RFC 3370 section 3.2, repeated by RFC 5754 section 3.2: in CMS an RSA
        // PKCS #1 v1.5 signature value is identified by rsaEncryption whatever the
        // digest, which SignerInfo carries in digestAlgorithm. It is what Cms\Builder
        // emits.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            signatureOid: SignatureVerifier::OID_RSA_ENCRYPTION,
        );

        $this->assertSame(Authority::tsa()->certDer, $this->verifier->verify($token));
    }

    public function testVerifyRejectsAnRsaEncryptionTokenWhoseSignatureIsWrong(): void
    {
        // The digest comes from a field outside the signature, and the signature
        // still has to verify under it.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            signatureOid: SignatureVerifier::OID_RSA_ENCRYPTION,
        );

        $swapped = \str_replace(Authority::tsa()->certDer, Authority::expiredTsa()->certDer, $token);
        $this->assertNotSame($token, $swapped);

        $this->expectException(Exception::class);
        $this->verifier->verify($swapped);
    }

    public function testVerifyRejectsAlteredContent(): void
    {
        // The message-digest signed attribute binds the eContent, so swapping it is
        // caught even though the attributes themselves are untouched.
        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            \hash('sha256', 'payload', true),
            '2.16.840.1.101.3.4.2.1',
        ));
        $other = $this->der->tstInfo(\hash('sha256', 'another payload', true), '2.16.840.1.101.3.4.2.1');
        $original = $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1');

        $this->assertSame(\strlen($original), \strlen($other));
        $tampered = \str_replace($original, $other, $token);
        $this->assertNotSame($token, $tampered);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not cover the encapsulated content/');
        $this->verifier->verify($tampered);
    }

    public function testVerifyRejectsATokenSignedByAnotherKey(): void
    {
        // Signed by the ltv CA, but carrying the ocsp CA certificate.
        $token = $this->token(Authority::ltv());
        $swapped = \str_replace(Authority::ltv()->certDer, Authority::ocsp()->certDer, $token);

        $this->expectException(Exception::class);
        $this->verifier->verify($swapped);
    }

    public function testVerifyRejectsATokenWithoutASignerInfo(): void
    {
        $token = $this->der->timestampToken($this->der->tstInfo(
            \hash('sha256', 'payload', true),
            '2.16.840.1.101.3.4.2.1',
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries no SignerInfo/');
        $this->verifier->verify($token);
    }

    public function testVerifyRejectsATokenWhoseSignerCertificateIsAbsent(): void
    {
        // Signed by the ocsp CA but carrying only an unrelated certificate, so no
        // embedded key answers to the SignerIdentifier.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            [Authority::ltv()->certDer],
            null,
            false,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not embed the signer certificate/');
        $this->verifier->verify($token);
    }

    public function testVerifyAcceptsASignerNamedBySubjectKeyIdentifier(): void
    {
        // SignerIdentifier ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier [0] }.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            [],
            null,
            true,
            true,
        );

        $this->verifier->verify($token);
        $this->expectNotToPerformAssertions();
    }

    public function testVerifyResolvesASubjectKeyIdentifierPastACertificateCarryingNone(): void
    {
        // RFC 5280 section 4.2.1.2 only recommends the extension, so a bag may hold a
        // certificate with none. subjectKeyIdentifier() answers '' for it, so an empty
        // SignerIdentifier is refused outright.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            [Authority::noKeyId()->certDer],
            null,
            true,
            true,
        );

        $this->assertSame(Authority::tsa()->certDer, $this->verifier->verify($token));
    }

    public function testVerifyRejectsASubjectKeyIdentifierNoBagMemberCarries(): void
    {
        // The only embedded certificate has no subjectKeyIdentifier, so it answers to
        // the empty identifier and matches no real one.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            [Authority::noKeyId()->certDer],
            null,
            false,
            true,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not embed the signer certificate/');
        $this->verifier->verify($token);
    }

    public function testVerifyRejectsAnUnknownSubjectKeyIdentifier(): void
    {
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            [Authority::ltv()->certDer],
            null,
            false,
            true,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not embed the signer certificate/');
        $this->verifier->verify($token);
    }

    /**
     * @return array<string, array{callable(Asn1, Der): string}>
     */
    public static function malformedSignedDataProvider(): array
    {
        return [
            'eContentType not an oid' => [
                static fn(Asn1 $asn1, Der $_der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3)
                            . $asn1->encodeSet('')
                            . $asn1->encodeSequence($asn1->encodeInteger(1) . $asn1->encodeContext(0, ''))
                            . $asn1->encodeSet(''),
                    ),
                ),
            ],
            'encapsulated content not tagged [0]' => [
                static fn(Asn1 $asn1, Der $_der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3)
                            . $asn1->encodeSet('')
                            . $asn1->encodeSequence(
                                $asn1->encodeObjectIdentifier(Der::OID_TST_INFO) . $asn1->encodeInteger(1),
                            )
                            . $asn1->encodeSet(''),
                    ),
                ),
            ],
            'signerInfos member not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3)
                            . $asn1->encodeSet('')
                            . $asn1->encodeSequence(
                                $asn1->encodeObjectIdentifier(Der::OID_TST_INFO)
                                    . $asn1->encodeContext(
                                        0,
                                        $asn1->encodeOctetString($der->tstInfo('x', '2.16.840.1.101.3.4.2.1')),
                                    ),
                            )
                            . $asn1->encodeSet($asn1->encodeInteger(1)),
                    ),
                ),
            ],
            'signedAttrs not tagged [0]' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeSet('') . $asn1->encodeSequence('') . $asn1->encodeOctetString('sig'),
                ),
            ],
            'digest algorithm not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(0, self::digestAttributes($asn1, $der)) . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                    $asn1->encodeInteger(1),
                ),
            ],
            'digest algorithm has no oid' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(0, self::digestAttributes($asn1, $der)) . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                    $asn1->encodeSequence($asn1->encodeInteger(1)),
                ),
            ],
            'digest algorithm not supported' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(0, self::digestAttributes($asn1, $der)) . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                    $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.2.5')),
                ),
            ],
            'attribute values not a set' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(
                        0,
                        $asn1->encodeSequence(
                            $asn1->encodeObjectIdentifier('1.2.840.113549.1.9.3') . $asn1->encodeInteger(1),
                        ),
                    ) . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                ),
            ],
            'attribute carries two values' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(
                        0,
                        $asn1->encodeSequence(
                            $asn1->encodeObjectIdentifier('1.2.840.113549.1.9.3')
                                . $asn1->encodeSet(
                                    $asn1->encodeObjectIdentifier(Der::OID_TST_INFO)
                                        . $asn1->encodeObjectIdentifier(Der::OID_TST_INFO),
                                ),
                        ),
                    ) . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                ),
            ],
            'signature not an octet string' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(0, $der->attribute('1.2.840.113549.1.9.4', $asn1->encodeOctetString('x')))
                        . $asn1->encodeSequence('')
                        . $asn1->encodeInteger(1),
                ),
            ],
            'no encapsulated content' => [
                static fn(Asn1 $asn1, Der $der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3)
                            . $asn1->encodeSet('')
                            . $asn1->encodeSequence($asn1->encodeObjectIdentifier(Der::OID_TST_INFO))
                            . $asn1->encodeSet($asn1->encodeSequence(
                                $asn1->encodeInteger(1)
                                    . $asn1->encodeSequence('')
                                    . $asn1->encodeSequence($asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1'))
                                    . $asn1->encodeContext(0, $der->attribute(
                                        '1.2.840.113549.1.9.4',
                                        $asn1->encodeOctetString('x'),
                                    ))
                                    . $asn1->encodeSequence('')
                                    . $asn1->encodeOctetString('sig'),
                            )),
                    ),
                ),
            ],
            'encapsulated content not an octet string' => [
                static fn(Asn1 $asn1, Der $_der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3)
                            . $asn1->encodeSet('')
                            . $asn1->encodeSequence(
                                $asn1->encodeObjectIdentifier(Der::OID_TST_INFO)
                                    . $asn1->encodeContext(0, $asn1->encodeInteger(1)),
                            )
                            . $asn1->encodeSet($asn1->encodeSequence(
                                $asn1->encodeInteger(1)
                                    . $asn1->encodeSequence('')
                                    . $asn1->encodeSequence('')
                                    . $asn1->encodeContext(0, '')
                                    . $asn1->encodeSequence('')
                                    . $asn1->encodeOctetString('sig'),
                            )),
                    ),
                ),
            ],
            'no message-digest attribute' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(0, $der->attribute(
                        '1.2.840.113549.1.9.3',
                        $asn1->encodeObjectIdentifier(Der::OID_TST_INFO),
                    )) . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                ),
            ],
            'signed attribute not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(0, $asn1->encodeInteger(1)) . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                ),
            ],
            'unsupported digest algorithm' => [
                static fn(Asn1 $asn1, Der $der): string => self::signerInfoToken(
                    $asn1,
                    $der,
                    $asn1->encodeContext(0, $der->attribute('1.2.840.113549.1.9.4', $asn1->encodeOctetString('x')))
                        . $asn1->encodeSequence('')
                        . $asn1->encodeOctetString('sig'),
                    $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.2.5')),
                ),
            ],
            'not a signed data' => [
                static fn(Asn1 $asn1, Der $_der): string => $asn1->encodeSequence(
                    $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1') . $asn1->encodeContext(0, ''),
                ),
            ],
            'encap not a sequence' => [
                static fn(Asn1 $asn1, Der $_der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3) . $asn1->encodeSet('') . $asn1->encodeInteger(1)
                            . $asn1->encodeSet($asn1->encodeSequence('')),
                    ),
                ),
            ],
            'signer info not a sequence' => [
                static fn(Asn1 $asn1, Der $_der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3) . $asn1->encodeSet('') . $asn1->encodeSequence('')
                            . $asn1->encodeSet($asn1->encodeInteger(1)),
                    ),
                ),
            ],
            'signer info without signed attributes' => [
                static fn(Asn1 $asn1, Der $_der): string => self::contentInfo(
                    $asn1,
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(3) . $asn1->encodeSet('') . $asn1->encodeSequence('')
                            . $asn1->encodeSet($asn1->encodeSequence(
                                $asn1->encodeInteger(1) . $asn1->encodeSequence('') . $asn1->encodeSequence('')
                                    . $asn1->encodeSequence(''),
                            )),
                    ),
                ),
            ],
        ];
    }

    /**
     * @param callable(Asn1, Der): string $build
     */
    #[DataProvider('malformedSignedDataProvider')]
    public function testVerifyRejectsMalformedStructures(callable $build): void
    {
        $this->expectException(Exception::class);
        $this->verifier->verify($build($this->asn1, $this->der));
    }

    public function testVerifyRejectsAContentTypeThatDoesNotMatchTheEncapsulatedContent(): void
    {
        // RFC 5652 sections 5.3 and 11.1: eContentType is outside the signature, so
        // it is compared with the signed content-type attribute.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            contentTypeOid: '1.2.840.113549.1.7.1',
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/content-type does not match/');
        $this->verifier->verify($token);
    }

    public function testVerifyRejectsAMissingContentTypeAttribute(): void
    {
        $asn1 = $this->asn1;
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $signedAttrs = $this->der->attribute(
            '1.2.840.113549.1.9.4',
            $asn1->encodeOctetString(\hash('sha256', $tstInfo, true)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/no content-type attribute/');
        $this->verifier->verify($this->signedToken($tstInfo, $signedAttrs));
    }

    public function testVerifyRejectsADuplicateSignedAttribute(): void
    {
        $asn1 = $this->asn1;
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $contentType = $this->der->attribute('1.2.840.113549.1.9.3', $asn1->encodeObjectIdentifier(Der::OID_TST_INFO));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Duplicate signed attribute/');
        $this->verifier->verify($this->signedToken($tstInfo, $contentType . $contentType));
    }

    public function testVerifyRejectsAnUnboundedSignedAttribute(): void
    {
        // Attribute ::= SEQUENCE { attrType, attrValues SET OF } (RFC 5652 section
        // 5.3), with nothing after the two.
        $asn1 = $this->asn1;
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $padded = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.9.3')
                . $asn1->encodeSet($asn1->encodeObjectIdentifier(Der::OID_TST_INFO))
                . $asn1->encodeOctetString('x'),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signed attribute/');
        $this->verifier->verify($this->signedToken($tstInfo, $padded));
    }

    public function testVerifyRejectsASigningCertificateNamingAnotherCertificate(): void
    {
        // RFC 5035: the attribute binds the signature to one certificate rather than
        // to its key, so a certificate reissued over the same key does not match.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            essCertDer: Authority::ltv()->certDer,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/names another certificate/');
        $this->verifier->verify($token);
    }

    /**
     * Malformed ESS signing-certificate attribute values.
     *
     * @return array<string, array{callable(Asn1): string, string}>
     */
    public static function malformedEssCertIdProvider(): array
    {
        return [
            'value not a sequence' => [
                static fn(Asn1 $asn1): string => $asn1->encodeOctetString('x'),
                'Invalid signing-certificate',
            ],
            'certs not a sequence' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeInteger(1)),
                'Invalid signing-certificate',
            ],
            'certs empty' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeSequence('')),
                'Invalid signing-certificate',
            ],
            'ESSCertIDv2 not a sequence' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeSequence($asn1->encodeInteger(1))),
                'Invalid signing-certificate',
            ],
            'certHash not an octet string' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeSequence($asn1->encodeSequence($asn1->encodeInteger(
                    1,
                )))),
                'Invalid signing-certificate',
            ],
        ];
    }

    /**
     * @param callable(Asn1): string $build
     */
    #[DataProvider('malformedEssCertIdProvider')]
    public function testVerifyRejectsAMalformedSigningCertificateAttribute(callable $build, string $expected): void
    {
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $signedAttrs =
            self::digestAttributes($this->asn1, $this->der)
            . $this->der->attribute('1.2.840.113549.1.9.16.2.47', $build($this->asn1));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($expected, '/') . '/');
        $this->verifier->verify($this->signedToken($tstInfo, $signedAttrs));
    }

    public function testVerifyReadsAnExplicitEssCertIdHashAlgorithm(): void
    {
        // ESSCertIDv2 hashAlgorithm is OPTIONAL and DEFAULT SHA-256, so a token that
        // states SHA-384 has to be hashed with SHA-384 rather than with the default.
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $signedAttrs =
            self::digestAttributes($this->asn1, $this->der)
            . $this->der->attribute(
                '1.2.840.113549.1.9.16.2.47',
                $this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeSequence(
                    $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.2'))
                        . $this->asn1->encodeOctetString(\hash('sha384', Authority::ocsp()->certDer, true)),
                ))),
            );

        $this->verifier->verify($this->signedToken($tstInfo, $signedAttrs));
        $this->expectNotToPerformAssertions();
    }

    public function testVerifyRefusesTheLegacySigningCertificateAttributeByDefault(): void
    {
        // SigningCertificate (v1) hashes with SHA-1 by definition (RFC 2634).
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $signedAttrs =
            self::digestAttributes($this->asn1, $this->der)
            . $this->der->attribute(
                '1.2.840.113549.1.9.16.2.12',
                $this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeOctetString(\hash(
                    'sha1',
                    Authority::ocsp()->certDer,
                    true,
                ))))),
            );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Refusing the SHA-1 signing-certificate/');
        $this->verifier->verify($this->signedToken($tstInfo, $signedAttrs));
    }

    public function testVerifyAcceptsTheLegacySigningCertificateAttributeWhenAllowed(): void
    {
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $signedAttrs =
            self::digestAttributes($this->asn1, $this->der)
            . $this->der->attribute(
                '1.2.840.113549.1.9.16.2.12',
                $this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeOctetString(\hash(
                    'sha1',
                    Authority::ocsp()->certDer,
                    true,
                ))))),
            );

        (new SignedDataVerifier($this->asn1, allowSha1: true))->verify($this->signedToken($tstInfo, $signedAttrs));
        $this->expectNotToPerformAssertions();
    }

    public function testVerifyAcceptsATokenWithoutASigningCertificateAttribute(): void
    {
        // The attribute is optional in CMS at large, so it is checked when present
        // rather than demanded.
        $this->verifier->verify($this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            essCertDer: '',
        ));
        $this->expectNotToPerformAssertions();
    }

    public function testVerifyDemandsTheSigningCertificateAttributeWhenRequired(): void
    {
        // RFC 3161 section 2.4.2 requires the attribute of a timestamp token, and it
        // is the only signed field naming the signing certificate, sid and the
        // CertificateSet being covered by no signature.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            essCertDer: '',
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries no signing-certificate attribute/');
        (new SignedDataVerifier($this->asn1, requireSigningCertificate: true))->verify($token);
    }

    public function testVerifyAcceptsARequiredSigningCertificateAttributeThatIsPresent(): void
    {
        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            \hash('sha256', 'payload', true),
            '2.16.840.1.101.3.4.2.1',
        ));

        (new SignedDataVerifier($this->asn1, requireSigningCertificate: true))->verify($token);
        $this->expectNotToPerformAssertions();
    }

    public function testVerifyRejectsATokenWithTwoSignerInfos(): void
    {
        // RFC 3161 section 2.4.2: "The time-stamp token MUST NOT contain any
        // signatures other than the signature of the TSA."
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'),
            signerInfoCount: 2,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/more than one SignerInfo/');
        $this->verifier->verify($token);
    }

    public function testVerifyRejectsATokenWithASecondSignerInfosSet(): void
    {
        // The same RFC 3161 rule, with the second signature in a SET of its own
        // rather than in the one the message carries. signerInfos is read at its own
        // position rather than as the last element of the SignedData.
        $tstInfo = $this->der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1');

        $genuine = $this->signedDataFields($this->der->signedTimestampToken($tstInfo, signer: Authority::tsa()));
        $grafted = $this->signedDataFields($this->der->signedTimestampToken($tstInfo, signer: Authority::expiredTsa()));

        $token = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(Der::OID_SIGNED_DATA)
                . $this->asn1->encodeContext(
                    0,
                    $this->asn1->encodeSequence(
                        $genuine['head']
                        . $this->asn1->encodeContext(0, $genuine['certs'] . $grafted['certs'])
                        . $genuine['signerInfos']
                        . $grafted['signerInfos'],
                    ),
                ),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the SignedData signerInfos/');
        $this->verifier->verify($token);
    }

    /**
     * Split a token's SignedData into the fields a grafted one is reassembled from.
     *
     * @return array{head: string, certs: string, signerInfos: string} The version,
     *         digestAlgorithms and encapContentInfo as one blob, the CertificateSet
     *         content, and the complete signerInfos SET.
     */
    private function signedDataFields(string $cmsDer): array
    {
        $signedData = (new Certificate($this->asn1))->signedDataContent($cmsDer);

        $offset = 0;
        $head = '';
        for ($idx = 0; $idx < 3; ++$idx) {
            $head .= $this->asn1->readTlv($signedData, $offset)['raw'];
        }

        $certs = $this->asn1->readTlv($signedData, $offset);
        $signerInfos = $this->asn1->readTlv($signedData, $offset);

        return ['head' => $head, 'certs' => $certs['value'], 'signerInfos' => $signerInfos['raw']];
    }

    public function testVerifyRejectsASecondCertificatesField(): void
    {
        // RFC 5652 section 5.1 admits certificates [0] once, so the fields are
        // dispatched positionally rather than skipped by tag.
        $fields = $this->signedDataFields($this->token());
        $bag = $this->asn1->encodeContext(0, $fields['certs']);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries no SignerInfo/');
        $this->verifier->verify(self::contentInfo(
            $this->asn1,
            $this->asn1->encodeSequence($fields['head'] . $bag . $bag . $fields['signerInfos']),
        ));
    }

    public function testVerifyRejectsCrlsBeforeCertificates(): void
    {
        $fields = $this->signedDataFields($this->token());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries no SignerInfo/');
        $this->verifier->verify(self::contentInfo(
            $this->asn1,
            $this->asn1->encodeSequence(
                $fields['head']
                . $this->asn1->encodeContext(1, '')
                . $this->asn1->encodeContext(0, $fields['certs'])
                . $fields['signerInfos'],
            ),
        ));
    }

    public function testVerifyAcceptsAnEmptyCrlsFieldInItsPlace(): void
    {
        $fields = $this->signedDataFields($this->token());

        $this->verifier->verify(self::contentInfo(
            $this->asn1,
            $this->asn1->encodeSequence(
                $fields['head']
                . $this->asn1->encodeContext(0, $fields['certs'])
                . $this->asn1->encodeContext(1, '')
                . $fields['signerInfos'],
            ),
        ));
        $this->expectNotToPerformAssertions();
    }

    public function testVerifyRejectsASignerInfoVersionThatIsNotAnInteger(): void
    {
        // The version sits outside signedAttrs and is held to its tag: an OCTET
        // STRING there is a SignerInfo no validator reads.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid SignerInfo version/');
        $this->verifier->verify($this->tokenWithSignerInfoVersion($this->asn1->encodeOctetString("\x01")));
    }

    public function testVerifyRejectsASignerInfoVersionTooWideToDecode(): void
    {
        // Decoded as well as tag-checked, as Cms\Certificate does with the SignedData
        // version, so an INTEGER wider than a PHP integer is refused.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/integer out of range/');
        $this->verifier->verify($this->tokenWithSignerInfoVersion("\x02\x09" . \str_repeat("\x7F", 9)));
    }

    /**
     * A genuine token whose single SignerInfo carries the given version field.
     */
    private function tokenWithSignerInfoVersion(string $version): string
    {
        $fields = $this->signedDataFields($this->token());

        $setOffset = 0;
        $set = $this->asn1->readTlv($fields['signerInfos'], $setOffset);
        $infoOffset = 0;
        $info = $this->asn1->readTlv($set['value'], $infoOffset);

        $versionOffset = 0;
        $this->asn1->readTlv($info['value'], $versionOffset);

        return self::contentInfo(
            $this->asn1,
            $this->asn1->encodeSequence(
                $fields['head'] . $this->asn1->encodeContext(0, $fields['certs'])
                    . $this->asn1->encodeSet($this->asn1->encodeSequence(
                        $version . \substr($info['value'], $versionOffset),
                    )),
            ),
        );
    }

    public function testVerifyRejectsAFieldAfterTheSignerInfoSignature(): void
    {
        // RFC 5652 section 5.3 puts unsignedAttrs [1] last, so an element carrying
        // another tag is refused.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid SignerInfo field after the signature/');
        $this->verifier->verify($this->tokenWithSignerInfoTail($this->asn1->encodeNull()));
    }

    public function testVerifyAcceptsUnsignedAttributesAfterTheSignature(): void
    {
        $this->verifier->verify($this->tokenWithSignerInfoTail($this->asn1->encodeContext(1, '')));
        $this->expectNotToPerformAssertions();
    }

    public function testVerifyRejectsBytesAfterTheUnsignedAttributes(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the SignerInfo unsigned attributes/');
        $this->verifier->verify($this->tokenWithSignerInfoTail(
            $this->asn1->encodeContext(1, '') . $this->asn1->encodeNull(),
        ));
    }

    /**
     * A genuine token whose single SignerInfo carries the given extra field.
     */
    private function tokenWithSignerInfoTail(string $tail): string
    {
        $fields = $this->signedDataFields($this->token());

        $setOffset = 0;
        $set = $this->asn1->readTlv($fields['signerInfos'], $setOffset);
        $infoOffset = 0;
        $info = $this->asn1->readTlv($set['value'], $infoOffset);

        return self::contentInfo(
            $this->asn1,
            $this->asn1->encodeSequence(
                $fields['head'] . $this->asn1->encodeContext(0, $fields['certs'])
                    . $this->asn1->encodeSet($this->asn1->encodeSequence($info['value'] . $tail)),
            ),
        );
    }

    public function testVerifyChecksADetachedSignatureAgainstTheContentGiven(): void
    {
        // The CMS this library emits for a PDF is detached, so the content is
        // supplied by the caller.
        $builder = new Builder($this->asn1);
        $leaf = Authority::ltvLeaf();
        $key = \openssl_pkey_get_private((string) \file_get_contents(__DIR__ . '/../data/ltv_cert.key'));
        self::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

        $cms = $builder->sign('the document bytes', $leaf->certDer, $key, [], 'sha256', 1_700_000_000);

        $this->assertSame($leaf->certDer, $this->verifier->verify($cms, 'the document bytes'));
    }

    public function testVerifyRejectsADetachedSignatureOverOtherContent(): void
    {
        $builder = new Builder($this->asn1);
        $leaf = Authority::ltvLeaf();
        $key = \openssl_pkey_get_private((string) \file_get_contents(__DIR__ . '/../data/ltv_cert.key'));
        self::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

        $cms = $builder->sign('the document bytes', $leaf->certDer, $key, [], 'sha256', 1_700_000_000);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/message digest does not cover/');
        $this->verifier->verify($cms, 'other bytes');
    }

    public function testVerifyRejectsAContentCarryingMessageWhenContentIsSupplied(): void
    {
        // A message carrying content of its own is not the message the caller is
        // checking, whatever the supplied octets hash to.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries its own encapsulated content/');
        $this->verifier->verify($this->token(), 'payload');
    }

    public function testVerifyRejectsTrailingBytesAfterTheContentInfo(): void
    {
        // The input has to be exactly one ContentInfo, with no trailing bytes.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid CMS structure/');
        $this->verifier->verify($this->token() . "\x00\x00trailing");
    }

    public function testVerifyRejectsAnEmptySubjectKeyIdentifier(): void
    {
        // An empty identifier names nothing, and would match every embedded
        // certificate carrying no subjectKeyIdentifier extension.
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $signedAttrs =
            $this->der->attribute('1.2.840.113549.1.9.3', $this->asn1->encodeObjectIdentifier(Der::OID_TST_INFO))
            . $this->der->attribute(
                '1.2.840.113549.1.9.4',
                $this->asn1->encodeOctetString(\hash('sha256', $tstInfo, true)),
            );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid SignerIdentifier/');
        $this->verifier->verify($this->signedToken($tstInfo, $signedAttrs, sid: "\x80\x00"));
    }

    public function testVerifyRejectsASha1MessageDigestByDefault(): void
    {
        // A SHA-1 message-digest attribute is refused unless the caller opts in, as a
        // SHA-1 signature algorithm is.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Refusing the SHA-1 digest/');
        $this->verifier->verify($this->sha1Token());
    }

    public function testVerifyAcceptsASha1MessageDigestWhenAllowed(): void
    {
        (new SignedDataVerifier($this->asn1, allowSha1: true))->verify($this->sha1Token());
        $this->expectNotToPerformAssertions();
    }

    /**
     * A token whose SignerInfo binds the content with SHA-1.
     */
    private function sha1Token(): string
    {
        $tstInfo = $this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1');
        $signedAttrs =
            $this->der->attribute('1.2.840.113549.1.9.3', $this->asn1->encodeObjectIdentifier(Der::OID_TST_INFO))
            . $this->der->attribute(
                '1.2.840.113549.1.9.4',
                $this->asn1->encodeOctetString(\hash('sha1', $tstInfo, true)),
            );

        return $this->signedToken(
            $tstInfo,
            $signedAttrs,
            $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier('1.3.14.3.2.26')),
        );
    }

    /**
     * Build a genuinely signed token around arbitrary signed attributes.
     *
     * The signature covers signedAttrs alone, so the identifier and the digest
     * algorithm can be varied without invalidating it.
     *
     * @param string|null $digestAlgorithm SignerInfo digestAlgorithm, or null for SHA-256.
     * @param string|null $sid             SignerIdentifier, or null for issuerAndSerialNumber.
     */
    private function signedToken(
        string $tstInfo,
        string $signedAttrs,
        ?string $digestAlgorithm = null,
        ?string $sid = null,
    ): string {
        $asn1 = $this->asn1;
        $tsa = Authority::ocsp();
        $algorithm = $digestAlgorithm ?? $asn1->encodeSequence($asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1'));

        $fields = (new Certificate($asn1))->fields($tsa->certDer);

        $signerInfo = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
                . ($sid ?? $asn1->encodeSequence($fields['issuer'] . $fields['serial']))
                . $algorithm
                . $asn1->encodeContext(0, $signedAttrs)
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID) . $asn1->encodeNull())
                . $asn1->encodeOctetString($tsa->sign($asn1->encodeSet($signedAttrs))),
        );

        $encap = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier(Der::OID_TST_INFO)
                . $asn1->encodeContext(0, $asn1->encodeOctetString($tstInfo)),
        );

        return self::contentInfo(
            $asn1,
            $asn1->encodeSequence(
                $asn1->encodeInteger(3) . $asn1->encodeSet($algorithm) . $encap . $asn1->encodeContext(0, $tsa->certDer)
                    . $asn1->encodeSet($signerInfo),
            ),
        );
    }

    /**
     * The content-type and message-digest attributes a well-formed token carries.
     */
    private static function digestAttributes(Asn1 $asn1, Der $der): string
    {
        $tstInfo = $der->tstInfo('x', '2.16.840.1.101.3.4.2.1');

        return (
            $der->attribute('1.2.840.113549.1.9.3', $asn1->encodeObjectIdentifier(Der::OID_TST_INFO))
            . $der->attribute('1.2.840.113549.1.9.4', $asn1->encodeOctetString(\hash('sha256', $tstInfo, true)))
        );
    }

    /**
     * A token whose SignerInfo tail (signed attributes onwards) is supplied verbatim.
     *
     * @param string      $tail            signedAttrs, signatureAlgorithm, and signature.
     * @param string|null $digestAlgorithm SignerInfo digestAlgorithm, or null for SHA-256.
     */
    private static function signerInfoToken(Asn1 $asn1, Der $der, string $tail, ?string $digestAlgorithm = null): string
    {
        $encap = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier(Der::OID_TST_INFO)
                . $asn1->encodeContext(0, $asn1->encodeOctetString($der->tstInfo('x', '2.16.840.1.101.3.4.2.1'))),
        );

        $signerInfo = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
            . $asn1->encodeSequence('')
            . ($digestAlgorithm ?? $asn1->encodeSequence($asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1')))
            . $tail,
        );

        return self::contentInfo(
            $asn1,
            $asn1->encodeSequence(
                $asn1->encodeInteger(3) . $asn1->encodeSet('') . $encap . $asn1->encodeSet($signerInfo),
            ),
        );
    }

    /**
     * Wrap SignedData content as a ContentInfo.
     */
    private static function contentInfo(Asn1 $asn1, string $signedData): string
    {
        return $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );
    }
}
