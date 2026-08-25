<?php

declare(strict_types=1);

/**
 * CertificateTest.php
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
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Credentials;
use Test\Fixture\Der;

/**
 * Certificate Test
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Certificate::class)]
final class CertificateTest extends TestCase
{
    private Asn1 $asn1;

    private Certificate $certificate;

    private Der $der;

    private string $leafPem = '';

    private string $leafDer = '';

    private string $caDer = '';

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->certificate = new Certificate($this->asn1);
        $this->der = new Der($this->asn1);
        $this->leafPem = (string) \file_get_contents(__DIR__ . '/../data/ocsp_leaf.pem');
        $this->leafDer = Certificate::pemToDer($this->leafPem);
        $this->caDer = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem'));
    }

    public function testFieldsReadsSubjectNotIssuer(): void
    {
        // The leaf subject (CN=...leaf) differs from its issuer (CN=...root CA),
        // so this proves the subject field is read, not the issuer field.
        $fields = $this->certificate->fields($this->leafDer);
        $this->assertStringContainsString('tc-lib-pdf-sign leaf', $fields['subject']);
        $this->assertStringNotContainsString('root CA', $fields['subject']);
        $this->assertStringContainsString('root CA', $fields['issuer']);
        $this->assertNotSame('', $fields['public_key']);
    }

    public function testFieldsReturnsTheSerialAsACompleteTlv(): void
    {
        $parsed = \openssl_x509_parse($this->leafPem);
        if (!\is_array($parsed)) {
            $this->fail('Unable to parse leaf certificate');
        }

        $serial = $this->certificate->fields($this->leafDer)['serial'];
        $this->assertSame("\x02", $serial[0]);

        $offset = 0;
        $tlv = $this->asn1->readTlv($serial, $offset);
        $this->assertSame(\strlen($serial), $offset);
        $this->assertSame(\strtolower($parsed['serialNumberHex']), \bin2hex($tlv['value']));
    }

    public function testFieldsPublicKeyDropsTheUnusedBitsOctet(): void
    {
        // An OCSP issuerKeyHash covers the subjectPublicKey BIT STRING value without
        // its leading unused-bits count, so the parsed bytes must be one shorter and
        // must themselves be the DER of the key.
        $offset = 0;
        $cert = $this->asn1->readTlv($this->leafDer, $offset);
        $tbsOffset = 0;
        $tbs = $this->asn1->readTlv($cert['value'], $tbsOffset);

        $inner = 0;
        for ($idx = 0; $idx < 6; ++$idx) {
            $this->asn1->readTlv($tbs['value'], $inner);
        }

        $spki = $this->asn1->readTlv($tbs['value'], $inner);
        $spkiOffset = 0;
        $this->asn1->readTlv($spki['value'], $spkiOffset);
        $bitString = $this->asn1->readTlv($spki['value'], $spkiOffset);

        $publicKey = $this->certificate->fields($this->leafDer)['public_key'];
        $this->assertSame(\strlen($bitString['value']) - 1, \strlen($publicKey));
        $this->assertSame(\substr($bitString['value'], 1), $publicKey);
    }

    public function testIsIssuerOfMatchesTheNamingLink(): void
    {
        $this->assertTrue($this->certificate->isIssuerOf($this->caDer, $this->leafDer));
        $this->assertFalse($this->certificate->isIssuerOf($this->leafDer, $this->caDer));
        // The root is self-issued.
        $this->assertTrue($this->certificate->isIssuerOf($this->caDer, $this->caDer));
    }

    public function testFieldsRejectsGarbage(): void
    {
        $this->expectException(Exception::class);
        $this->certificate->fields($this->asn1->encodeInteger(1));
    }

    public function testFieldsRejectsANonSequenceTbsCertificate(): void
    {
        $this->expectException(Exception::class);
        $this->certificate->fields($this->asn1->encodeSequence($this->asn1->encodeInteger(1)));
    }

    public function testPemToDerRoundTrip(): void
    {
        $this->assertSame($this->leafDer, Certificate::pemToDer(Certificate::derToPem($this->leafDer)));
    }

    public function testSignatureTimestampTokensReadsTheEmbeddedToken(): void
    {
        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            \hash('sha256', 'signature', true),
            '2.16.840.1.101.3.4.2.1',
        ));

        $this->assertSame(
            [$token],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes($this->der->attribute(
                '1.2.840.113549.1.9.16.2.14',
                $token,
            ))),
        );
    }

    public function testSignatureTimestampTokensDeduplicatesAndIgnoresOtherAttributes(): void
    {
        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            \hash('sha256', 'signature', true),
            '2.16.840.1.101.3.4.2.1',
        ));

        // Two attribute values and a second attribute of another type, both of which
        // an unsigned attribute set may carry.
        $attributes =
            $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.9.16.2.14')
                    . $this->asn1->encodeSet($token . $token),
            ) . $this->der->attribute('1.2.840.113549.1.9.16.2.25', $this->asn1->encodeNull());

        $this->assertSame(
            [$token],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes($attributes)),
        );
    }

    public function testSignatureTimestampTokensDropsAValueThatIsNotASequence(): void
    {
        $this->assertSame(
            [],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes($this->der->attribute(
                '1.2.840.113549.1.9.16.2.14',
                $this->asn1->encodeInteger(1),
            ))),
        );
    }

    public function testSignatureTimestampTokensDropsAValueThatIsNotASignedData(): void
    {
        // unsignedAttrs is covered by no signature, so a DER SEQUENCE that is not a
        // CMS SignedData is passed over rather than returned as a token.
        $this->assertSame(
            [],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes($this->der->attribute(
                '1.2.840.113549.1.9.16.2.14',
                $this->asn1->encodeSequence($this->asn1->encodeOctetString('<html>502 Bad Gateway</html>')),
            ))),
        );
    }

    public function testFieldsRejectsANonMinimalSerialNumber(): void
    {
        // X.690 section 8.3.2 forbids a leading zero octet whose successor's high
        // bit is clear, and OpenSSL will not load such a certificate at all.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Non-minimal ASN.1 integer encoding/');
        $this->certificate->fields($this->certificateWithSerial("\x02\x02\x00\x2A"));
    }

    public function testFieldsAcceptsASerialWiderThanAPhpInteger(): void
    {
        // The control: a conforming serial runs to 20 octets (RFC 5280 section
        // 4.1.2.2), too wide to decode, so only its encoding is checked.
        $serial = "\x02\x14" . \str_repeat("\x7F", 20);

        $this->assertSame($serial, $this->certificate->fields($this->certificateWithSerial($serial))['serial']);
    }

    /**
     * The ocsp leaf re-issued with the given serialNumber element, genuinely signed.
     */
    private function certificateWithSerial(string $serialTlv): string
    {
        $leafDer = Authority::leaf()->certDer;

        $offset = 0;
        $cert = $this->asn1->readTlv($leafDer, $offset);

        $tbsOffset = 0;
        $tbs = $this->asn1->readTlv($cert['value'], $tbsOffset);
        $rest = \substr($cert['value'], $tbsOffset);

        $inner = 0;
        $version = '';
        if ((\ord($tbs['value'][0]) & 0xE0) === 0xA0) {
            $version = $this->asn1->readTlv($tbs['value'], $inner)['raw'];
        }

        $this->asn1->readTlv($tbs['value'], $inner); // the original serialNumber
        $newTbs = $this->asn1->encodeSequence($version . $serialTlv . \substr($tbs['value'], $inner));

        $restOffset = 0;
        $algorithmId = $this->asn1->readTlv($rest, $restOffset);

        return $this->asn1->encodeSequence(
            $newTbs . $algorithmId['raw'] . $this->der->bitString(Authority::ocsp()->sign($newTbs)),
        );
    }

    public function testSignatureTimestampTokensPassesOverAMemberItCannotRead(): void
    {
        // unsignedAttrs is covered by no signature, so a member that is not an
        // Attribute is passed over and the genuine token beside it is still found.
        $token = $this->stubTimestampToken();
        $genuine = $this->timestampAttribute($token);

        $unreadable = [
            'member that is not a SEQUENCE' => $this->asn1->encodeInteger(1),
            'attrType that is not an OID' => $this->asn1->encodeSequence(
                $this->asn1->encodeOctetString('x') . $this->asn1->encodeSet("\x05\x00"),
            ),
            'attribute carrying a third field' => $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.9.16.2.14')
                    . $this->asn1->encodeSet($this->asn1->encodeSequence(''))
                    . $this->asn1->encodeOctetString('x'),
            ),
            'attribute whose own content is truncated' => $this->asn1->encodeSequence("\x30\x7F"),
            'attribute value SET carrying a truncated member' => $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.9.16.2.14') . $this->asn1->encodeSet("\x30\x7F"),
            ),
        ];

        foreach ($unreadable as $label => $member) {
            $this->assertSame(
                [$token],
                $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes($genuine . $member)),
                $label,
            );
        }
    }

    public function testSignatureTimestampTokensKeepsWhatItReadBeforeATruncatedMember(): void
    {
        // A member whose length octets overrun the field ends the tiling of the SET,
        // so there is no next member to move to. What was read before it stands.
        $token = $this->stubTimestampToken();

        $this->assertSame(
            [$token],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes(
                $this->timestampAttribute($token) . "\x30\x7F",
            )),
        );
    }

    public function testSignatureTimestampTokensKeepsATokenBesideAnUnreadableValue(): void
    {
        // The same rule inside one attribute: attrValues is a SET OF and is as
        // unsigned as the attribute holding it, so the token beside the bad value is
        // still found.
        $token = $this->stubTimestampToken();

        $unreadable = [
            'value whose length octets overrun the SET' => "\x30\x82\xFF\xFF",
            'value truncated inside its own length' => "\x30\x7F",
            'value using the high tag number form' => "\x3F\x01\x00",
        ];

        foreach ($unreadable as $label => $value) {
            $attribute = $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.9.16.2.14')
                    . $this->asn1->encodeSet($token . $value),
            );

            $this->assertSame(
                [$token],
                $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes($attribute)),
                $label,
            );
        }
    }

    public function testSignatureTimestampTokensGivesUpOnAnAttributeItCannotOpen(): void
    {
        // The outer rule stands: an attribute whose own type or value SET cannot be
        // read names no token, and only that attribute is given up on.
        $token = $this->stubTimestampToken();

        $this->assertSame(
            [$token],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes(
                $this->timestampAttribute($token)
                    . $this->asn1->encodeSequence(
                        $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.9.16.2.14') . "\x31\x7F",
                    ),
            )),
        );
    }

    /**
     * A ContentInfo that Certificate::signedDataContent() reads, standing in for a token.
     */
    private function stubTimestampToken(): string
    {
        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2')
                . $this->asn1->encodeContext(0, $this->asn1->encodeSequence('')),
        );
    }

    /**
     * An id-aa-signatureTimeStampToken unsigned Attribute carrying one token.
     */
    private function timestampAttribute(string $tokenDer): string
    {
        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.9.16.2.14') . $this->asn1->encodeSet($tokenDer),
        );
    }

    public function testSignatureTimestampTokensIsEmptyWithoutUnsignedAttributes(): void
    {
        $this->assertSame([], $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes(null)));
        $this->assertSame(
            [],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes(null, $this->asn1->encodeContext(
                2,
                '',
            ))),
        );
    }

    public function testSignerInfosSkipsTheOptionalFieldsInOrder(): void
    {
        // The content octets of each member are returned, which is what the callers
        // walk. certificates [0] and crls [1] are skipped, in that order.
        $head = $this->signedDataHead();
        $content = $this->asn1->encodeInteger(1);

        $this->assertSame(
            [$content],
            $this->certificate->signerInfos(
                $head . $this->asn1->encodeContext(0, '') . $this->asn1->encodeContext(1, '')
                    . $this->asn1->encodeSet($this->asn1->encodeSequence($content)),
                $this->headLength(),
            ),
        );
    }

    public function testSignerInfosRejectsAMemberThatIsNotASequence(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid SignerInfo/');
        $this->certificate->signerInfos(
            $this->signedDataHead() . $this->asn1->encodeSet($this->asn1->encodeInteger(1)),
            $this->headLength(),
        );
    }

    public function testSignerInfosRejectsTrailingBytes(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the SignedData signerInfos/');
        $this->certificate->signerInfos(
            $this->signedDataHead() . $this->asn1->encodeSet($this->asn1->encodeSequence(''))
                . $this->asn1->encodeNull(),
            $this->headLength(),
        );
    }

    public function testSignerInfosRejectsASignedDataThatEndsAfterTheOptionalFields(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries no SignerInfo/');
        $this->certificate->signerInfos(
            $this->signedDataHead() . $this->asn1->encodeContext(0, ''),
            $this->headLength(),
        );
    }

    public function testEncapsulatedContentRejectsContentWhenTheCallerExpectsNone(): void
    {
        $signedData = $this->signedDataHead();

        $offset = 0;
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries its own encapsulated content/');
        $this->certificate->encapsulatedContent($signedData, $offset, true);
    }

    public function testEncapsulatedContentReadsADetachedSignedData(): void
    {
        $encap = $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'));
        $signedData = $this->signedDataHead($encap);

        $offset = 0;
        $this->assertSame(
            [$this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'), ''],
            $this->certificate->encapsulatedContent($signedData, $offset, true),
        );
        $this->assertSame(\strlen($signedData), $offset);
    }

    /**
     * The version, digestAlgorithms and encapContentInfo of a SignedData.
     */
    private function signedDataHead(?string $encap = null): string
    {
        return (
            $this->asn1->encodeInteger(1)
            . $this->asn1->encodeSet('')
            . (
                $encap ?? $this->asn1->encodeSequence(
                    $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1')
                        . $this->asn1->encodeContext(0, $this->asn1->encodeOctetString('content')),
                )
            )
        );
    }

    private function headLength(): int
    {
        return \strlen($this->signedDataHead());
    }

    /**
     * A CMS whose single SignerInfo carries the given unsignedAttrs content.
     *
     * @param string|null $attributes Concatenated Attribute entries, or null for none.
     * @param string      $tail       A field emitted in place of unsignedAttrs [1].
     */
    private function cmsWithUnsignedAttributes(?string $attributes, string $tail = ''): string
    {
        $signerInfo = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->asn1->encodeSequence('')
            . $this->asn1->encodeSequence('')
            . $this->asn1->encodeContext(0, '')
            . $this->asn1->encodeSequence('')
            . $this->asn1->encodeOctetString('sig')
            . ($attributes === null ? $tail : $this->asn1->encodeContext(1, $attributes)),
        );

        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2')
                . $this->asn1->encodeContext(
                    0,
                    $this->asn1->encodeSequence($this->signedDataHead() . $this->asn1->encodeSet($signerInfo)),
                ),
        );
    }

    public function testPemToDerReadsABodyPastThePcreBacktrackLimit(): void
    {
        // A lazily quantified pattern over the body exhausts pcre.backtrack_limit
        // above roughly a megabyte of PEM and returns false, so the armour is located
        // with strpos() instead.
        $limit = (int) \ini_get('pcre.backtrack_limit');
        $der = $this->leafDer . \str_repeat("\x00", \max(0, $limit - \strlen($this->leafDer)));
        $pem = Certificate::derToPem($der);

        $this->assertGreaterThan($limit, \strlen($pem));

        // The body is recovered, so the failure is about the certificate rather than
        // about the armour: these bytes are a certificate followed by padding.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid PEM certificate/');
        Certificate::pemToDer($pem);
    }

    public function testPemToDerRejectsInvalidBase64(): void
    {
        $this->expectException(Exception::class);
        Certificate::pemToDer("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----");
    }

    public function testPemToDerRejectsEmptyBody(): void
    {
        $this->expectException(Exception::class);
        Certificate::pemToDer("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----");
    }

    public function testDeduplicatePreservesFirstSeenOrder(): void
    {
        $this->assertSame(['a', 'b', 'c'], Certificate::deduplicate(['a', 'b', 'a', 'c', 'b']));
    }

    public function testFromSignedDataReturnsEmbeddedCertificates(): void
    {
        $token = $this->der->timestampToken($this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1'), [
            $this->leafDer,
            $this->caDer,
        ]);

        $this->assertSame([$this->leafDer, $this->caDer], $this->certificate->fromSignedData($token));
    }

    public function testFromSignedDataSkipsATaggedCertificateChoicesAlternative(): void
    {
        // CertificateChoices ::= CHOICE { certificate, ..., v2AttrCert [2], other [3] }.
        // Everything but the plain certificate is tagged, and none of them is one.
        $token = $this->der->timestampToken($this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1'), [
            $this->asn1->encodeContext(3, $this->asn1->encodeInteger(1)),
            $this->leafDer,
        ]);

        $this->assertSame([$this->leafDer], $this->certificate->fromSignedData($token));
    }

    public function testFromSignedDataDropsAMemberThatIsNotACertificate(): void
    {
        // certificates [0] sits outside signedAttrs and is covered by no signature,
        // so every member is parsed as a certificate before it is kept.
        $junk = $this->asn1->encodeSequence($this->asn1->encodeInteger(7));

        $token = $this->der->timestampToken($this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1'), [
            $junk,
            $this->leafDer,
            $this->asn1->encodeSequence($this->asn1->encodeOctetString('not a certificate either')),
        ]);

        $this->assertSame([$this->leafDer], $this->certificate->fromSignedData($token));
    }

    public function testFromSignedDataReturnsEmptyWhenNoCertificates(): void
    {
        $token = $this->der->timestampToken($this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1'));

        $this->assertSame([], $this->certificate->fromSignedData($token));
    }

    public function testFromSignedDataRejectsANonSignedDataContentInfo(): void
    {
        $notSignedData = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1')
                . $this->asn1->encodeContext(0, $this->asn1->encodeSequence('')),
        );

        $this->expectException(Exception::class);
        $this->certificate->fromSignedData($notSignedData);
    }

    public function testSignedDataContentRejectsGarbage(): void
    {
        $this->expectException(Exception::class);
        $this->certificate->signedDataContent($this->asn1->encodeInteger(1));
    }

    /**
     * Bytes appended at each layer of a CMS ContentInfo.
     *
     * The input has to be exactly one ContentInfo, and each layer of it exactly one
     * element, with no trailing bytes.
     *
     * @return array<string, array{string}>
     */
    public static function trailingCmsBytesProvider(): array
    {
        $asn1 = new Asn1();
        $der = new Der($asn1);
        $token = $der->timestampToken($der->tstInfo('x', '2.16.840.1.101.3.4.2.1'));

        $signedData = $asn1->encodeSequence(
            $asn1->encodeInteger(3) . $asn1->encodeSet('') . $asn1->encodeSequence('') . $asn1->encodeSet(''),
        );
        $oid = $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2');

        return [
            'after the ContentInfo' => [$token . "\x00\x00trailing"],
            'after the content in the ContentInfo' => [
                $asn1->encodeSequence($oid . $asn1->encodeContext(0, $signedData) . $asn1->encodeInteger(1)),
            ],
            'after the SignedData in the content' => [
                $asn1->encodeSequence($oid . $asn1->encodeContext(0, $signedData . $asn1->encodeInteger(1))),
            ],
        ];
    }

    #[DataProvider('trailingCmsBytesProvider')]
    public function testSignedDataContentRejectsTrailingBytes(string $cms): void
    {
        $this->expectException(Exception::class);
        $this->certificate->signedDataContent($cms);
    }

    /**
     * Encapsulated content that carries a field this reader would have skipped.
     *
     * RFC 5652 section 5.2 puts nothing after eContentType and eContent, so a
     * further field is refused.
     *
     * @return array<string, array{string}>
     */
    public static function malformedEncapsulatedContentProvider(): array
    {
        $asn1 = new Asn1();
        $oid = $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1');
        $octets = $asn1->encodeOctetString('content');

        return [
            'trailing bytes after eContent' => [
                $asn1->encodeSequence($oid . $asn1->encodeContext(0, $octets) . $asn1->encodeInteger(1)),
            ],
            'two octet strings in eContent' => [
                $asn1->encodeSequence($oid . $asn1->encodeContext(0, $octets . $octets)),
            ],
            'eContent not tagged [0]' => [$asn1->encodeSequence($oid . $octets)],
            'eContent absent' => [$asn1->encodeSequence($oid)],
            'eContentType not an OID' => [
                $asn1->encodeSequence($asn1->encodeInteger(1) . $asn1->encodeContext(0, $octets)),
            ],
            'encapContentInfo not a sequence' => [$asn1->encodeInteger(1)],
        ];
    }

    #[DataProvider('malformedEncapsulatedContentProvider')]
    public function testEncapsulatedContentRejectsAMalformedEncapContentInfo(string $encap): void
    {
        $signedData = $this->asn1->encodeInteger(3) . $this->asn1->encodeSet('') . $encap;

        $offset = 0;
        $this->expectException(Exception::class);
        $this->certificate->encapsulatedContent($signedData, $offset);
    }

    public function testEncapsulatedContentReadsTheTypeAndTheOctets(): void
    {
        $encap = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1')
                . $this->asn1->encodeContext(0, $this->asn1->encodeOctetString('content')),
        );
        $signedData = $this->asn1->encodeInteger(3) . $this->asn1->encodeSet('') . $encap . $this->asn1->encodeSet('');

        $offset = 0;
        $this->assertSame(
            [$this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'), 'content'],
            $this->certificate->encapsulatedContent($signedData, $offset),
        );
        $this->assertSame(\strlen($signedData) - 2, $offset);
    }

    public function testFieldsRejectsANonBitStringPublicKey(): void
    {
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1) // serialNumber
                . $this->asn1->encodeSequence('') // signature
                . $this->asn1->encodeSequence('') // issuer
                . $this->asn1->encodeSequence("\x18\x0F20230101000000Z\x18\x0F20330101000000Z") // validity
                . $this->asn1->encodeSequence('') // subject
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeSequence('') . $this->asn1->encodeOctetString('not a bit string'),
                ),
        );

        $this->expectException(Exception::class);
        $this->certificate->fields($this->asn1->encodeSequence($tbs));
    }

    public function testSignedDataContentRejectsAnUntaggedContent(): void
    {
        $cms = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $this->asn1->encodeSequence(''),
        );

        $this->expectException(Exception::class);
        $this->certificate->signedDataContent($cms);
    }

    public function testSignedDataContentRejectsANonSequenceSignedData(): void
    {
        $cms = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2')
                . $this->asn1->encodeContext(0, $this->asn1->encodeInteger(1)),
        );

        $this->expectException(Exception::class);
        $this->certificate->signedDataContent($cms);
    }

    public function testFromSignedDataReturnsEmptyWhenTheSignedDataIsTruncated(): void
    {
        // No certificates field and no signerInfos: nothing to collect.
        $cms = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2')
                . $this->asn1->encodeContext(
                    0,
                    $this->asn1->encodeSequence(
                        $this->asn1->encodeInteger(3) . $this->asn1->encodeSet('') . $this->asn1->encodeSequence(''),
                    ),
                ),
        );

        $this->assertSame([], $this->certificate->fromSignedData($cms));
    }

    /**
     * TBSCertificate fields that are the wrong ASN.1 type.
     *
     * Every field is tag-checked, so a structure that merely nests SEQUENCEs does
     * not pass for a certificate.
     *
     * @return array<string, array{list<string>, string}>
     */
    public static function malformedTbsFieldProvider(): array
    {
        $asn1 = new Asn1();
        $name = $asn1->encodeSequence('');
        $validity = $asn1->encodeSequence("\x18\x0F20230101000000Z\x18\x0F20330101000000Z");
        $spki = $asn1->encodeSequence($asn1->encodeSequence('') . "\x03\x02\x00\x01");

        return [
            'serial is not an integer' => [
                [$asn1->encodeOctetString('x'), $asn1->encodeSequence(''), $name, $validity, $name, $spki],
                'serial number',
            ],
            'issuer is not a name' => [
                [$asn1->encodeInteger(1), $asn1->encodeSequence(''), $asn1->encodeInteger(2), $validity, $name, $spki],
                'issuer',
            ],
            'validity is not a sequence' => [
                [$asn1->encodeInteger(1), $asn1->encodeSequence(''), $name, $asn1->encodeInteger(2), $name, $spki],
                'validity',
            ],
            'validity is not two times' => [
                [
                    $asn1->encodeInteger(1),
                    $asn1->encodeSequence(''),
                    $name,
                    $asn1->encodeSequence($asn1->encodeInteger(1) . $asn1->encodeInteger(2)),
                    $name,
                    $spki,
                ],
                'Time',
            ],
            'subject is not a name' => [
                [$asn1->encodeInteger(1), $asn1->encodeSequence(''), $name, $validity, $asn1->encodeInteger(2), $spki],
                'subject',
            ],
            'spki is not a sequence' => [
                [
                    $asn1->encodeInteger(1),
                    $asn1->encodeSequence(''),
                    $name,
                    $validity,
                    $name,
                    $asn1->encodeInteger(2),
                ],
                'subjectPublicKeyInfo',
            ],
            // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
            // subjectPublicKey BIT STRING }, so the field before the key is a
            // SEQUENCE. OpenSSL refuses a certificate whose is not.
            'spki algorithm is not an algorithm identifier' => [
                [
                    $asn1->encodeInteger(1),
                    $asn1->encodeSequence(''),
                    $name,
                    $validity,
                    $name,
                    $asn1->encodeSequence($asn1->encodeSet('') . "\x03\x02\x00\x01"),
                ],
                'subjectPublicKeyInfo algorithm',
            ],
        ];
    }

    /**
     * @param list<string> $fields
     */
    #[DataProvider('malformedTbsFieldProvider')]
    public function testFieldsRejectsAFieldOfTheWrongType(array $fields, string $expected): void
    {
        $tbs = $this->asn1->encodeSequence(\implode('', $fields));
        $cert = $this->asn1->encodeSequence($tbs . $this->asn1->encodeSequence('') . "\x03\x02\x00\x01");

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($expected, '/') . '/');
        $this->certificate->fields($cert);
    }

    public function testFieldsDoesNotTakeAnyContextTagForTheVersion(): void
    {
        // version [0] is the only context tag admissible as the first element of a
        // TBSCertificate, so the tag is matched exactly rather than by class.
        $asn1 = $this->asn1;
        $tbs = $asn1->encodeSequence(
            $asn1->encodeContext(3, $asn1->encodeInteger(2))
                . $asn1->encodeInteger(1)
                . $asn1->encodeSequence('')
                . $asn1->encodeSequence('')
                . $asn1->encodeSequence("\x18\x0F20230101000000Z\x18\x0F20330101000000Z")
                . $asn1->encodeSequence('')
                . $asn1->encodeSequence($asn1->encodeSequence('') . "\x03\x02\x00\x01"),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/serial number/');
        $this->certificate->fields($asn1->encodeSequence($tbs . $asn1->encodeSequence('') . "\x03\x02\x00\x01"));
    }

    public function testFieldsReadsTheValidityPeriod(): void
    {
        $fields = $this->certificate->fields(Authority::ocsp()->certDer);

        $parsed = \openssl_x509_parse(Authority::ocsp()->certPem);
        if (!\is_array($parsed)) {
            $this->fail('Unable to parse the fixture certificate');
        }

        $this->assertSame($parsed['validFrom_time_t'], $fields['not_before']);
        $this->assertSame($parsed['validTo_time_t'], $fields['not_after']);
    }

    public function testAssertValidAtAcceptsATimeInsideTheInterval(): void
    {
        $fields = $this->certificate->fields(Authority::ocsp()->certDer);
        $this->certificate->assertValidAt(Authority::ocsp()->certDer, $fields['not_before'] + 1);
        $this->expectNotToPerformAssertions();
    }

    public function testAssertValidAtRejectsATimeBeforeNotBefore(): void
    {
        $fields = $this->certificate->fields(Authority::ocsp()->certDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not yet valid/');
        $this->certificate->assertValidAt(Authority::ocsp()->certDer, $fields['not_before'] - 86_400);
    }

    public function testAssertValidAtRejectsATimeAfterNotAfter(): void
    {
        $fields = $this->certificate->fields(Authority::ocsp()->certDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/has expired/');
        $this->certificate->assertValidAt(Authority::ocsp()->certDer, $fields['not_after'] + 86_400);
    }

    public function testAssertValidAtToleratesClockSkew(): void
    {
        $fields = $this->certificate->fields(Authority::ocsp()->certDer);
        $this->certificate->assertValidAt(Authority::ocsp()->certDer, $fields['not_before'] - 60, 300);
        $this->expectNotToPerformAssertions();
    }

    public function testAssertUsableForSigningAcceptsASigningCertificate(): void
    {
        // The leaf fixture carries keyUsage digitalSignature, nonRepudiation.
        $this->certificate->assertUsableForSigning(Authority::leaf()->certDer);
        $this->expectNotToPerformAssertions();
    }

    public function testAssertUsableForSigningRejectsACertificateThatCannotSign(): void
    {
        // The CA fixture carries keyUsage keyCertSign, cRLSign: it may sign
        // certificates and CRLs, and nothing else.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not admit signing/');
        $this->certificate->assertUsableForSigning(Authority::ocsp()->certDer);
    }

    public function testAssertUsableForSigningAcceptsACertificateWithoutTheExtension(): void
    {
        // RFC 5280 section 4.2.1.3: a certificate with no KeyUsage extension is
        // unrestricted, so there is nothing to refuse.
        $cred = Credentials::make('rsa', commonName: 'no key usage');
        if ($cred === null) {
            $this->markTestSkipped('Unable to generate an RSA credential');
        }

        $this->certificate->assertUsableForSigning($cred['cert_der']);
        $this->expectNotToPerformAssertions();
    }

    public function testAssertUsableForSigningRejectsAnUnreadableCertificate(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Malformed ASN.1/');
        $this->certificate->assertUsableForSigning('not a certificate');
    }

    public function testAssertUsableForSigningRejectsAnUndecodableKeyUsage(): void
    {
        // The extension is decoded from its DER rather than from OpenSSL's
        // rendering. The value here is a UTF8String of "Digital Signature", which is
        // not the BIT STRING the OID names.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate keyUsage/');
        $this->certificate->assertUsableForSigning($this->certificateWithExtensions(
            "keyUsage=DER:0c:11:44:69:67:69:74:61:6c:20:53:69:67:6e:61:74:75:72:65\n",
        ));
    }

    public function testPemToDerRejectsABundleOfCertificates(): void
    {
        // fullchain.pem, as every issuance tool writes it. When the first
        // certificate's length is divisible by three its base64 carries no padding,
        // so a concatenation of the two bodies decodes cleanly.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/more than one certificate/');
        Certificate::pemToDer($this->leafPem . (string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem'));
    }

    public function testPemToDerRejectsABodyThatIsNotACertificate(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid PEM certificate/');
        Certificate::pemToDer(\base64_encode('hello world'));
    }

    public function testPemToDerRejectsACertificateWithTrailingBytes(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid PEM certificate/');
        Certificate::pemToDer(Certificate::derToPem($this->leafDer . "\x00"));
    }

    public function testPemToDerRejectsAPrivateKey(): void
    {
        // PKCS#8 is a DER SEQUENCE, as is nearly everything a PEM file holds, so the
        // armour has to say CERTIFICATE and the body has to parse as one.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not hold a certificate/');
        Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ltv_cert.key'));
    }

    public function testPemToDerRejectsAPublicKey(): void
    {
        $key = \openssl_pkey_get_public($this->leafPem);
        $this->assertNotFalse($key);
        $details = \openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        $this->assertArrayHasKey('key', $details);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not hold a certificate/');
        Certificate::pemToDer($details['key'] ?? '');
    }

    public function testPemToDerRejectsMismatchedArmourLabels(): void
    {
        $mixed = \str_replace('-----END CERTIFICATE-----', '-----END PRIVATE KEY-----', $this->leafPem);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not hold a certificate/');
        Certificate::pemToDer($mixed);
    }

    public function testPemToDerRejectsAnUnarmouredBodyThatIsNotACertificate(): void
    {
        // A body with no armour is accepted, but it has to be a certificate too.
        $key = Certificate::pemToDer($this->leafPem);
        $this->assertNotSame('', $key);

        $spki = \base64_encode($this->asn1->encodeSequence($this->asn1->encodeOctetString(\str_repeat('x', 200))));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid PEM certificate/');
        Certificate::pemToDer($spki);
    }

    public function testFieldsRejectsBytesAppendedAfterTheSignature(): void
    {
        // A real certificate with content appended inside its outer SEQUENCE. Every
        // field the callers quote still reads, so the whole structure is walked.
        // OpenSSL refuses it too.
        $offset = 0;
        $outer = $this->asn1->readTlv($this->leafDer, $offset);
        $padded = $this->asn1->encodeSequence($outer['value'] . $this->asn1->encodeOctetString(\str_repeat('X', 300)));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the certificate signature/');
        $this->certificate->fields($padded);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function malformedCertificateShapeProvider(): array
    {
        $asn1 = new Asn1();
        $name = $asn1->encodeSequence('');
        $validity = $asn1->encodeSequence("\x18\x0F20230101000000Z\x18\x0F20330101000000Z");
        $spki = $asn1->encodeSequence($asn1->encodeSequence('') . "\x03\x02\x00\x01");
        $body = $asn1->encodeInteger(1) . $asn1->encodeSequence('') . $name . $validity . $name;

        return [
            'no signatureAlgorithm and no signatureValue' => [
                $asn1->encodeSequence($asn1->encodeSequence($body . $spki)),
                'Malformed ASN.1 structure',
            ],
            'signatureValue is not a bit string' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($body . $spki) . $asn1->encodeSequence('') . $asn1->encodeInteger(2),
                ),
                'Invalid certificate signature',
            ],
            'tbs signature algorithm is not a sequence' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(1) . $asn1->encodeInteger(2) . $name . $validity . $name . $spki,
                    )
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Invalid TBSCertificate signature algorithm',
            ],
            'trailing bytes in the subjectPublicKeyInfo' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence(
                        $body
                            . $asn1->encodeSequence(
                                $asn1->encodeSequence('') . "\x03\x02\x00\x01" . $asn1->encodeOctetString('x'),
                            ),
                    )
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Trailing bytes in the subjectPublicKeyInfo',
            ],
            'trailing bytes in the validity' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence(
                        $asn1->encodeInteger(1)
                        . $asn1->encodeSequence('')
                        . $name
                        . $asn1->encodeSequence(
                            "\x18\x0F20230101000000Z\x18\x0F20330101000000Z" . $asn1->encodeOctetString('x'),
                        )
                        . $name
                        . $spki,
                    )
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Trailing bytes in the certificate validity',
            ],
            'unknown field after the subjectPublicKeyInfo' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($body . $spki . $asn1->encodeOctetString('x'))
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Invalid TBSCertificate field after the subjectPublicKeyInfo',
            ],
            'a second extensions field' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence(
                        $body . $spki . $asn1->encodeContext(3, $asn1->encodeSequence(''))
                            . $asn1->encodeContext(3, $asn1->encodeSequence('')),
                    )
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Trailing bytes after the TBSCertificate extensions',
            ],
            'the extensions tag wraps more than one element' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence(
                        $body . $spki . $asn1->encodeContext(3, $asn1->encodeSequence('') . $asn1->encodeSequence('')),
                    )
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Invalid DER for certificate extensions',
            ],
            // RFC 5280 section 4.1.2.1 shapes version [0] EXPLICIT as one INTEGER of
            // v1(0), v2(1) or v3(2), and the wrapper holds that element and nothing
            // else.
            'the version field does not wrap one integer' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($asn1->encodeContext(0, $asn1->encodeSequence('')) . $body . $spki)
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Invalid certificate version',
            ],
            'a version this reader does not know' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($asn1->encodeContext(0, $asn1->encodeInteger(3)) . $body . $spki)
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Unsupported certificate version: 4',
            ],
            // RFC 5280 section 4.1.2.9: extensions appear only in a v3 certificate.
            'extensions in a certificate that is not v3' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($body . $spki . $asn1->encodeContext(3, $asn1->encodeSequence('')))
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
                'Extensions in a certificate of version 1',
            ],
            // RFC 5280 section 4.1.1.2: the outer signatureAlgorithm must carry the
            // same identifier as the TBSCertificate signature field. Only the inner
            // one is covered by the signature.
            'the two signature algorithms differ' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($body . $spki)
                    . $asn1->encodeSequence($asn1->encodeNull())
                    . "\x03\x02\x00\x01",
                ),
                'The certificate signature algorithms differ',
            ],
        ];
    }

    #[DataProvider('malformedCertificateShapeProvider')]
    public function testFieldsRejectsAStructureThatIsNotACertificate(string $certDer, string $expected): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($expected, '/') . '/');
        $this->certificate->fields($certDer);
    }

    public function testFieldsAcceptsTheOptionalUniqueIdentifiers(): void
    {
        // issuerUniqueID [1] and subjectUniqueID [2] IMPLICIT sit between the
        // subjectPublicKeyInfo and the extensions, and a v2 certificate carries them.
        $asn1 = $this->asn1;
        $name = $asn1->encodeSequence('');
        $spki = $asn1->encodeSequence($asn1->encodeSequence('') . "\x03\x02\x00\x01");
        $tbs = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
            . $asn1->encodeSequence('')
            . $name
            . $asn1->encodeSequence("\x18\x0F20230101000000Z\x18\x0F20330101000000Z")
            . $name
            . $spki
            . "\x81\x02\x00\x01"
            . "\x82\x02\x00\x02",
        );

        $fields = $this->certificate->fields($asn1->encodeSequence(
            $tbs . $asn1->encodeSequence('') . "\x03\x02\x00\x01",
        ));

        $this->assertSame($name, $fields['issuer']);
        $this->assertSame(
            [],
            $this->certificate->extensions($asn1->encodeSequence(
                $tbs . $asn1->encodeSequence('') . "\x03\x02\x00\x01",
            )),
        );
    }

    public function testFromSignedDataDropsAMemberThatIsOnlyShapedLikeACertificate(): void
    {
        // The CertificateSet is covered by no signature, so a blob that merely nests
        // the SEQUENCEs a certificate begins with does not pass for one.
        $asn1 = $this->asn1;
        $name = $asn1->encodeSequence('');
        $payload = $asn1->encodeOctetString(\str_repeat('NOT-A-CERTIFICATE', 40));
        $fake = $asn1->encodeSequence(
            $asn1->encodeSequence(
                $asn1->encodeInteger(1)
                    . $asn1->encodeSequence('')
                    . $name
                    . $asn1->encodeSequence("\x18\x0F20230101000000Z\x18\x0F20330101000000Z")
                    . $name
                    . $asn1->encodeSequence($asn1->encodeSequence('') . "\x03\x02\x00\x01"),
            )
                . $payload,
        );

        $signedData = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
                . $asn1->encodeSet('')
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'))
                . $asn1->encodeContext(0, $fake . $this->leafDer)
                . $asn1->encodeSet(''),
        );
        $cms = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );

        $this->assertSame([$this->leafDer], $this->certificate->fromSignedData($cms));

        // A caller that publishes the message verbatim asks for the strict reading,
        // dropping the member leaving its bytes in the message either way.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CertificateSet holds a member that is not a certificate/');
        $this->certificate->fromSignedData($cms, true);
    }

    public function testFromSignedDataAcceptsAWellFormedSignedDataWhenStrict(): void
    {
        // The strict reading bounds the whole structure, so a message that carries
        // certificates [0], crls [1] and one SignerInfo, each well formed and in the
        // order RFC 5652 section 5.1 gives them, passes it.
        $asn1 = $this->asn1;
        $signedData = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
                . $asn1->encodeSet('')
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'))
                . $asn1->encodeContext(0, $this->leafDer . $this->caDer)
                . $asn1->encodeContext(1, $asn1->encodeSequence(''))
                . $asn1->encodeSet($asn1->encodeSequence('')),
        );
        $cms = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );

        $this->assertSame([$this->leafDer, $this->caDer], $this->certificate->fromSignedData($cms, true));
    }

    public function testFromSignedDataRefusesATaggedCertificateSetMemberWhenStrict(): void
    {
        // RFC 5652 section 10.2.2 types the field as a set of CertificateChoices, so
        // a tagged alternative is dropped by the lenient reading and refused by the
        // strict one.
        $asn1 = $this->asn1;
        $signedData = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
                . $asn1->encodeSet('')
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'))
                . $asn1->encodeContext(0, $this->leafDer . $asn1->encodeContext(3, \str_repeat('X', 64)))
                . $asn1->encodeSet($asn1->encodeSequence('')),
        );
        $cms = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );

        $this->assertSame([$this->leafDer], $this->certificate->fromSignedData($cms));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CertificateSet holds a member that is not a certificate/');
        $this->certificate->fromSignedData($cms, true);
    }

    public function testFromSignedDataBoundsTheCrlsFieldWhenStrict(): void
    {
        // crls [1] sits outside the signature and travels with the message, so the
        // strict reading walks and bounds it.
        $asn1 = $this->asn1;
        $signedData = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
                . $asn1->encodeSet('')
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'))
                . $asn1->encodeContext(0, $this->leafDer)
                . $asn1->encodeContext(1, $asn1->encodeOctetString(\str_repeat('X', 64)))
                . $asn1->encodeSet($asn1->encodeSequence('')),
        );
        $cms = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );

        $this->assertSame([$this->leafDer], $this->certificate->fromSignedData($cms));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/crls field holds a member that is not revocation information/');
        $this->certificate->fromSignedData($cms, true);
    }

    /**
     * The SignedData head fields, each replaced by something the walk would step over
     * on the strength of nothing.
     *
     * @return array<string, array{string, string, string}>
     */
    public static function malformedSignedDataHeadProvider(): array
    {
        $asn1 = new Asn1();
        $version = $asn1->encodeInteger(1);
        $digests = $asn1->encodeSet($asn1->encodeSequence($asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1')));

        return [
            'version is an OCTET STRING of chosen bytes' => [
                $asn1->encodeOctetString(\str_repeat('X', 64)),
                $digests,
                'Invalid SignedData field before the certificates',
            ],
            'version is an INTEGER wider than a reader can weigh' => [
                "\x02\x09\x01" . \str_repeat("\x00", 8),
                $digests,
                'ASN.1 integer out of range',
            ],
            'digestAlgorithms is not a SET' => [
                $version,
                $asn1->encodeOctetString(\str_repeat('X', 64)),
                'Invalid SignedData field before the certificates',
            ],
            'digestAlgorithms holds a member that is not an AlgorithmIdentifier' => [
                $version,
                $asn1->encodeSet($asn1->encodeOctetString(\str_repeat('X', 64))),
                'Invalid SignedData digest AlgorithmIdentifier',
            ],
            'a digestAlgorithms member carries chosen bytes after its OID' => [
                $version,
                $asn1->encodeSet($asn1->encodeSequence(
                    $asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1')
                        . $asn1->encodeOctetString(\str_repeat('X', 64)),
                )),
                'Unsupported SignedData digest AlgorithmIdentifier parameters',
            ],
        ];
    }

    #[DataProvider('malformedSignedDataHeadProvider')]
    public function testFromSignedDataBoundsTheHeadWhenStrict(
        string $version,
        string $digestAlgorithms,
        string $message,
    ): void {
        // version, digestAlgorithms and encapContentInfo are as far outside the
        // signature as the certificate bag is, so the strict reading holds them to
        // their shapes as well.
        $asn1 = $this->asn1;
        $signedData = $asn1->encodeSequence(
            $version
                . $digestAlgorithms
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'))
                . $asn1->encodeContext(0, $this->leafDer)
                . $asn1->encodeSet($asn1->encodeSequence('')),
        );
        $cms = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );

        $this->assertSame([$this->leafDer], $this->certificate->fromSignedData($cms));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $this->certificate->fromSignedData($cms, true);
    }

    public function testFromSignedDataBoundsTheCertificateSetSizeWhenStrict(): void
    {
        // The bag is unauthenticated, so its size is bounded. Ocsp\Client holds a
        // response's certs [0] to the same number.
        $asn1 = $this->asn1;
        $bag = \str_repeat($this->leafDer, Certificate::MAX_EMBEDDED_CERTIFICATES + 1);
        $signedData = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
                . $asn1->encodeSet('')
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'))
                . $asn1->encodeContext(0, $bag)
                . $asn1->encodeSet($asn1->encodeSequence('')),
        );
        $cms = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );

        $this->assertCount(Certificate::MAX_EMBEDDED_CERTIFICATES + 1, $this->certificate->fromSignedData($cms));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CertificateSet holds more than 32 certificates/');
        $this->certificate->fromSignedData($cms, true);
    }

    public function testFromSignedDataDropsAMemberItCannotReadUnlessStrict(): void
    {
        // The lenient reading drops a member that does not parse as a certificate.
        // A member whose length octets overrun the field ends the tiling of the SET,
        // so there is no next member and what was read before it stands. The strict
        // reading stays fatal.
        $asn1 = $this->asn1;
        $signedData = $asn1->encodeSequence(
            $asn1->encodeInteger(1)
                . $asn1->encodeSet('')
                . $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'))
                . $asn1->encodeContext(0, $this->leafDer . "\x30\x82\xFF\xFF")
                . $asn1->encodeSet($asn1->encodeSequence('')),
        );
        $cms = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.7.2') . $asn1->encodeContext(0, $signedData),
        );

        $this->assertSame([$this->leafDer], $this->certificate->fromSignedData($cms));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Malformed ASN.1 length/');
        $this->certificate->fromSignedData($cms, true);
    }

    public function testToDerAcceptsBothEncodings(): void
    {
        $this->assertSame($this->leafDer, Certificate::toDer($this->leafPem));
        $this->assertSame($this->leafDer, Certificate::toDer($this->leafDer));
    }

    public function testToDerRejectsDerThatIsNotACertificate(): void
    {
        $this->expectException(Exception::class);
        Certificate::toDer($this->asn1->encodeSequence($this->asn1->encodeOctetString(\str_repeat('x', 200))));
    }

    public function testAssertUsableForCrlSigningAcceptsAnAuthority(): void
    {
        $this->expectNotToPerformAssertions();
        (new Certificate($this->asn1))->assertUsableForCrlSigning($this->caDer);
    }

    public function testAssertUsableForCrlSigningRejectsAnEndEntityCertificate(): void
    {
        // RFC 5280 section 6.3.3 (f): a valid signature by an end-entity key is not
        // an authority over a revocation list.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not a certification authority/');
        (new Certificate($this->asn1))->assertUsableForCrlSigning($this->leafDer);
    }

    public function testAssertUsableForCrlSigningRejectsACaWithoutTheCrlSignUsage(): void
    {
        // RFC 5280 section 4.2.1.3: a CA that may sign certificates but whose
        // keyUsage does not admit cRLSign has not been authorised to sign a list.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not admit CRL signing/');
        (new Certificate($this->asn1))->assertUsableForCrlSigning($this->certificateWithExtensions(
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n",
        ));
    }

    public function testAssertUsableForCrlSigningRejectsAnUndecodableBasicConstraints(): void
    {
        // The extension is decoded from its DER rather than from OpenSSL's
        // rendering. The value here is a UTF8String of "CA:TRUE", which is not the
        // SEQUENCE the OID names.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate basicConstraints/');
        (new Certificate($this->asn1))->assertUsableForCrlSigning($this->certificateWithExtensions("basicConstraints=DER:0c:07:43:41:3a:54:52:55:45\n"
        . "keyUsage=DER:0c:08:43:52:4c:20:53:69:67:6e\n"));
    }

    /**
     * A self-signed certificate carrying the given OpenSSL extension directives.
     */
    private function certificateWithExtensions(string $extensions): string
    {
        $path = \tempnam(\sys_get_temp_dir(), 'tclps');
        if ($path === false) {
            $this->markTestSkipped('Unable to create a temporary OpenSSL configuration');
        }

        \file_put_contents($path, "[req]\ndistinguished_name=dn\n[dn]\n[crafted]\n" . $extensions);

        try {
            $config = ['config' => $path, 'digest_alg' => 'sha256', 'private_key_bits' => 2048];
            $key = \openssl_pkey_new($config);
            if (!$key instanceof \OpenSSLAsymmetricKey) {
                $this->markTestSkipped('RSA key generation is not available');
            }

            $csr = \openssl_csr_new(['commonName' => 'crafted'], $key, $config);
            if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
                $this->markTestSkipped('CSR generation failed');
            }

            $cert = \openssl_csr_sign($csr, null, $key, 365, [...$config, 'x509_extensions' => 'crafted']);
            if (!$cert instanceof \OpenSSLCertificate) {
                $this->markTestSkipped('Certificate signing failed');
            }

            $pem = '';
            \openssl_x509_export($cert, $pem);

            return Certificate::pemToDer($pem);
        } finally {
            \unlink($path);
        }
    }

    public function testClearOpenSslErrorsDrainsTheQueue(): void
    {
        Certificate::clearOpenSslErrors();
        $this->assertFalse(\openssl_pkey_get_public('not a key'));

        Certificate::clearOpenSslErrors();
        $this->assertFalse(\openssl_error_string());
    }

    public function testFieldsRejectsTrailingBytes(): void
    {
        // The input has to be exactly one certificate, with nothing after the outer
        // SEQUENCE.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate structure/');
        $this->certificate->fields($this->leafDer . $this->caDer);
    }

    public function testExtendedKeyUsageReadsThePurposes(): void
    {
        // The OIDs the extension names, not the names a rendering gives them:
        // id-kp-OCSPSigning and id-kp-timeStamping.
        $this->assertSame(['1.3.6.1.5.5.7.3.9'], $this->certificate->extendedKeyUsage(Authority::responder()->certDer));
        $this->assertSame(['1.3.6.1.5.5.7.3.8'], $this->certificate->extendedKeyUsage(Authority::tsa()->certDer));
    }

    public function testExtendedKeyUsageRejectsAnUndecodableExtension(): void
    {
        // A purpose that is only the text OpenSSL would have printed for it is not a
        // KeyPurposeId.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate extendedKeyUsage/');
        $this->certificate->extendedKeyUsage($this->certificateWithExtensions(
            "extendedKeyUsage=DER:0c:0d:54:69:6d:65:20:53:74:61:6d:70:69:6e:67\n",
        ));
    }

    public function testExtendedKeyUsageIsNullWithoutTheExtension(): void
    {
        // RFC 5280 section 4.2.1.12: no extension means no purpose is excluded.
        $this->assertNull($this->certificate->extendedKeyUsage(Authority::leaf()->certDer));
    }

    public function testExtendedKeyUsageRejectsAnUnreadableCertificate(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Malformed ASN.1/');
        $this->certificate->extendedKeyUsage('not a certificate');
    }

    public function testIsCertificateAuthorityReadsBasicConstraints(): void
    {
        $this->assertTrue($this->certificate->isCertificateAuthority(Authority::ocsp()->certDer));
        $this->assertFalse($this->certificate->isCertificateAuthority(Authority::leaf()->certDer));
    }

    public function testIsCertificateAuthorityRejectsAnUnreadableCertificate(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Malformed ASN.1/');
        $this->certificate->isCertificateAuthority('not a certificate');
    }

    public function testSubjectKeyIdentifierReadsTheOctetString(): void
    {
        $extension = $this->certificate->extensions(Authority::leaf()->certDer)['2.5.29.14'] ?? null;
        $this->assertIsArray($extension);
        $this->assertSame(
            \substr($extension['value'], 2),
            $this->certificate->subjectKeyIdentifier(Authority::leaf()->certDer),
        );
    }

    public function testSubjectKeyIdentifierIsEmptyForAnUndecodableExtension(): void
    {
        // The extension is decoded from its DER, so bytes that are not a
        // KeyIdentifier name nothing.
        $this->assertSame(
            '',
            $this->certificate->subjectKeyIdentifier($this->certificateWithExtensions(
                "subjectKeyIdentifier=DER:41:42:3a:43:44\n",
            )),
        );
    }

    public function testSubjectKeyIdentifierIsEmptyWithoutTheExtension(): void
    {
        $this->assertSame('', $this->certificate->subjectKeyIdentifier($this->certificateWithExtensions('')));
    }

    public function testSubjectKeyIdentifierIsEmptyForAnExtensionThatIsNotAKeyIdentifier(): void
    {
        // KeyIdentifier ::= OCTET STRING (RFC 5280 section 4.2.1.2). A well-formed
        // element of another type is not one.
        $this->assertSame(
            '',
            $this->certificate->subjectKeyIdentifier($this->certificateWithExtensions(
                "subjectKeyIdentifier=DER:0c:03:41:42:43\n",
            )),
        );
    }

    public function testSubjectKeyIdentifierIsEmptyForAnUnreadableCertificate(): void
    {
        $this->assertSame('', $this->certificate->subjectKeyIdentifier('not a certificate'));
    }

    public function testExtendedKeyUsageIsCriticalReadsTheFlag(): void
    {
        // RFC 3161 section 2.3 requires the extension to be critical of a TSA.
        $this->assertTrue($this->certificate->extendedKeyUsageIsCritical(Authority::tsa()->certDer));
        $this->assertFalse($this->certificate->extendedKeyUsageIsCritical(Authority::leaf()->certDer));
    }

    public function testExtendedKeyUsageRejectsAMemberThatIsNotAPurpose(): void
    {
        // KeyPurposeId ::= OBJECT IDENTIFIER, so a member of another type is not a
        // purpose the key may serve.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate extendedKeyUsage/');
        $this->certificate->extendedKeyUsage($this->certificateWithExtensions("extendedKeyUsage=DER:30:03:02:01:01\n"));
    }

    public function testIsCertificateAuthorityIsFalseWithoutTheExtension(): void
    {
        // RFC 5280 section 4.2.1.9: no basicConstraints means the certificate may
        // not issue others.
        $this->assertFalse($this->certificate->isCertificateAuthority($this->certificateWithExtensions('')));
    }

    public function testIsCertificateAuthorityRejectsAMalformedCaFlag(): void
    {
        // A BOOLEAN is one content octet (X.690 section 8.2.1); any other length is
        // refused.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate basicConstraints/');
        $this->certificate->isCertificateAuthority($this->certificateWithExtensions(
            "basicConstraints=DER:30:04:01:02:ff:ff\n",
        ));
    }

    public function testIsCertificateAuthorityBoundsTheBasicConstraints(): void
    {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint
        // INTEGER OPTIONAL } has nothing after the two.
        // SEQUENCE { BOOLEAN TRUE, INTEGER 0, OCTET STRING "ignored" }
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes in the certificate basicConstraints/');
        $this->certificate->isCertificateAuthority($this->certificateWithExtensions(
            "basicConstraints=DER:30:0f:01:01:ff:02:01:00:04:07:69:67:6e:6f:72:65:64\n",
        ));
    }

    public function testIsCertificateAuthorityAcceptsAPathLenConstraint(): void
    {
        // SEQUENCE { BOOLEAN TRUE, INTEGER 0 } is what a CA with a path length
        // states. The value is bounded but not weighed.
        $this->assertTrue($this->certificate->isCertificateAuthority($this->certificateWithExtensions(
            "basicConstraints=DER:30:06:01:01:ff:02:01:00\n",
        )));
    }

    public function testIsCertificateAuthorityRejectsAFieldThatIsNotAPathLenConstraint(): void
    {
        // SEQUENCE { BOOLEAN TRUE, SEQUENCE { BOOLEAN FALSE } }
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate basicConstraints/');
        $this->certificate->isCertificateAuthority($this->certificateWithExtensions(
            "basicConstraints=DER:30:08:01:01:ff:30:03:01:01:00\n",
        ));
    }

    public function testExtendedKeyUsageRejectsARepeatedPurpose(): void
    {
        // A purpose stated twice is refused rather than collapsed, as
        // Asn1::decodeExtensions() refuses an extension type stated twice.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches(
            '/Duplicate certificate extendedKeyUsage purpose: 1\.3\.6\.1\.5\.5\.7\.3\.9/',
        );
        $this->certificate->extendedKeyUsage($this->certificateWithExtensions(
            "extendedKeyUsage=OCSPSigning,OCSPSigning\n",
        ));
    }

    public function testExtendedKeyUsageWithCriticalityAnswersBothOffOneDecode(): void
    {
        $this->assertSame(
            [['1.3.6.1.5.5.7.3.8'], true],
            $this->certificate->extendedKeyUsageWithCriticality(Authority::tsa()->certDer),
        );
        $this->assertSame(
            [['1.3.6.1.5.5.7.3.8'], false],
            $this->certificate->extendedKeyUsageWithCriticality(Authority::laxTsa()->certDer),
        );
        $this->assertSame(
            [null, false],
            $this->certificate->extendedKeyUsageWithCriticality(Authority::leaf()->certDer),
        );
    }

    public function testAssertUsableForSigningRejectsAMalformedKeyUsageBitCount(): void
    {
        // The unused-bits count of a BIT STRING is 0..7 (X.690 section 8.6.2).
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate keyUsage/');
        $this->certificate->assertUsableForSigning($this->certificateWithExtensions("keyUsage=DER:03:02:09:80\n"));
    }

    public function testSignatureTimestampTokensReadsNoTokenFromAnUnboundedUnsignedAttribute(): void
    {
        // Attribute ::= SEQUENCE { attrType, attrValues SET OF }, with nothing after
        // the two, so an attribute carrying a third field names no token. It is not
        // fatal, unsignedAttrs being covered by no signature.
        $asn1 = $this->asn1;
        $attribute = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.2.840.113549.1.9.16.2.14') . $asn1->encodeSet($asn1->encodeSequence(''))
                . $asn1->encodeOctetString('x'),
        );

        $this->assertSame(
            [],
            $this->certificate->signatureTimestampTokens($this->cmsWithUnsignedAttributes($attribute)),
        );
    }

    public function testExtensionsDecodesTheExtensionsFromTheCertificateDer(): void
    {
        // Read off the DER rather than OpenSSL's rendering, which flattens each
        // extension to a string.
        $extensions = $this->certificate->extensions(Authority::ltvLeaf()->certDer);

        // 2.5.29.31 is cRLDistributionPoints, 1.3.6.1.5.5.7.1.1 authorityInfoAccess.
        $this->assertArrayHasKey('2.5.29.31', $extensions);
        $this->assertArrayHasKey('1.3.6.1.5.5.7.1.1', $extensions);
        $this->assertFalse($extensions['2.5.29.31']['critical'] ?? true);

        // 2.5.29.15 is keyUsage, which the fixture marks critical.
        $this->assertTrue($extensions['2.5.29.15']['critical'] ?? false);
        $this->assertNotSame('', $extensions['2.5.29.31']['value'] ?? '');
    }

    public function testExtensionsIsEmptyForACertificateCarryingNone(): void
    {
        // A TBSCertificate whose optional [3] field is absent carries no extensions,
        // which is the empty map rather than an error.
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeContext(0, $this->asn1->encodeInteger(2))
                . $this->asn1->encodeInteger(7)
                . $this->asn1->encodeSequence('')
                . $this->asn1->encodeSequence('')
                . $this->asn1->encodeSequence("\x18\x0F20200101000000Z\x18\x0F20400101000000Z")
                . $this->asn1->encodeSequence('')
                . $this->asn1->encodeSequence($this->asn1->encodeSequence('') . "\x03\x02\x00\x01"),
        );
        $der = $this->asn1->encodeSequence($tbs . $this->asn1->encodeSequence('') . "\x03\x02\x00\x01");

        $this->assertSame([], $this->certificate->extensions($der));
    }

    public function testExtensionsRejectsAnUnparseableCertificate(): void
    {
        $this->expectException(Exception::class);
        $this->certificate->extensions('not a certificate');
    }
}
