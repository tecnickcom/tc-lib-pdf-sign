<?php

declare(strict_types=1);

/**
 * CrlTest.php
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

namespace Test\Ltv;

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Ltv\Crl;
use Com\Tecnick\Pdf\Sign\RevokedException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Der;

/**
 * CRL Test
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Crl::class)]
final class CrlTest extends TestCase
{
    /**
     * A moment inside the validity interval the fixture CRLs declare.
     */
    private const NOW = 1_800_000_000;

    private Asn1 $asn1;

    private Der $der;

    private Crl $crl;

    private string $issuerDer = '';

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->der = new Der($this->asn1);
        $this->crl = new Crl($this->asn1);
        $this->issuerDer = Authority::ocsp()->certDer;
    }

    public function testValidateReturnsTheBytesUnchanged(): void
    {
        $crl = $this->der->crl();
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateRejectsANonMinimalVersion(): void
    {
        // X.690 section 8.3.2 forbids a leading zero octet whose successor's high
        // bit is clear, and OpenSSL will not load the list. The version is decoded
        // rather than stepped over, so it inherits the rule, as
        // Cms\Certificate::version() and Ocsp\Client::explicitVersion() do.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Non-minimal ASN.1 integer encoding/');
        $this->crl->validate($this->crlWithVersion("\x02\x02\x00\x01"), $this->issuerDer, null, self::NOW);
    }

    public function testValidateAcceptsAMinimalVersion(): void
    {
        // The control: the range stays unchecked, a version outside the set RFC 5280
        // names still being an INTEGER.
        $crl = $this->crlWithVersion($this->asn1->encodeInteger(999));
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateRejectsANonMinimalRevocationEntrySerial(): void
    {
        // The serial is compared against the DER the certificate carries, and a
        // conforming one runs to 20 octets (RFC 5280 section 4.1.2.2), too wide to
        // decode, so only its minimality is checked.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Non-minimal ASN.1 integer encoding/');
        $this->crl->validate($this->crlWithRevokedEntry("\x02\x02\x00\x2A"), $this->issuerDer, null, self::NOW);
    }

    public function testValidateAcceptsAMinimalRevocationEntrySerial(): void
    {
        // The control: a serial wider than a PHP integer is accepted, only its
        // encoding being checked.
        $crl = $this->crlWithRevokedEntry("\x02\x14" . \str_repeat("\x7F", 20));
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    /**
     * A genuinely signed CRL carrying the given version element.
     */
    private function crlWithVersion(string $version): string
    {
        return $this->signedCrl($version, '');
    }

    /**
     * A genuinely signed CRL carrying one revocation entry with the given serial.
     */
    private function crlWithRevokedEntry(string $serial): string
    {
        return $this->signedCrl(
            $this->asn1->encodeInteger(1),
            $this->asn1->encodeSequence($this->asn1->encodeSequence(
                $serial . $this->der->generalizedTime(self::NOW - 86_400),
            )),
        );
    }

    /**
     * Assemble and sign a TBSCertList around a version and a revokedCertificates field.
     */
    private function signedCrl(string $version, string $revoked): string
    {
        $algorithmId = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID) . $this->asn1->encodeNull(),
        );

        $tbs = $this->asn1->encodeSequence(
            $version
            . $algorithmId
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $this->der->generalizedTime(1_900_000_000)
            . $revoked,
        );

        return $this->asn1->encodeSequence($tbs . $algorithmId . $this->der->bitString(Authority::ocsp()->sign($tbs)));
    }

    public function testValidateAcceptsARecentCrlWithoutNextUpdate(): void
    {
        // nextUpdate is OPTIONAL in RFC 5280, so a fresh list without one stands.
        $crl = $this->der->crl(self::NOW - 3600, null);
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateRejectsAStaleCrlWithoutNextUpdate(): void
    {
        // Without a nextUpdate the age bound is what limits how old the list may
        // be.
        $crl = $this->der->crl(self::NOW - Crl::DEFAULT_MAX_AGE - 86_400, null);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/too old/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateAgeLimitIsConfigurable(): void
    {
        $crl = $this->der->crl(self::NOW - 86_400, null);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/too old/');
        (new Crl($this->asn1, maxAge: 3600))->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateAgeLimitCanBeDisabled(): void
    {
        $crl = $this->der->crl(1_600_000_000, null);
        $this->assertSame($crl, (new Crl($this->asn1, maxAge: 0))->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testConstructorRejectsANegativeAgeLimit(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/age limit/');
        new Crl($this->asn1, maxAge: -1);
    }

    public function testClockSkewIsConfigurable(): void
    {
        // An hour ahead is outside the default skew and inside a widened one, as on
        // the OCSP and TSA sides.
        $crl = $this->der->crl(self::NOW + 3600, self::NOW + 86_400);

        $this->assertSame($crl, (new Crl($this->asn1, clockSkew: 7200))->validate(
            $crl,
            $this->issuerDer,
            null,
            self::NOW,
        ));
    }

    public function testTheDefaultClockSkewRejectsWhatAWidenedOneAccepts(): void
    {
        $crl = $this->der->crl(self::NOW + 3600, self::NOW + 86_400);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not yet valid/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testConstructorRejectsANegativeClockSkew(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/clock skew/');
        new Crl($this->asn1, clockSkew: -1);
    }

    public function testValidateDefaultsToTheCurrentTime(): void
    {
        $crl = $this->der->crl(\time() - 3600, null);
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null));
    }

    public function testValidateRejectsBytesThatAreNotACertificateList(): void
    {
        // The HTTP error body a distribution point returns is not revocation evidence.
        $this->expectException(Exception::class);
        $this->crl->validate('<html>404 Not Found</html>', $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsAnElementThatIsNotASequence(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid DER for CRL/');
        $this->crl->validate($this->asn1->encodeInteger(1), $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsEmptyBytes(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Empty CRL/');
        $this->crl->validate('', $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsTrailingBytes(): void
    {
        $this->expectException(Exception::class);
        $this->crl->validate($this->der->crl() . "\x00", $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsAListFromAnotherAuthority(): void
    {
        $crl = $this->der->crl(issuer: Authority::ltv()->subject($this->asn1), signer: Authority::ltv());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/issued by another authority/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsABrokenSignature(): void
    {
        // Names the right issuer, signed by the wrong key.
        $crl = $this->der->crl(signer: Authority::ltv());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not verify/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsAnExpiredList(): void
    {
        // Recent enough for the age bound, so this is the nextUpdate rule alone.
        $crl = $this->der->crl(self::NOW - 7200, self::NOW - 3600);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/has expired/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsAStaleListThatCarriesANextUpdate(): void
    {
        // RFC 5280 section 5.1.2.5 makes nextUpdate optional but a conforming CA
        // emits it, so the age bound applies whether or not one is present.
        $crl = $this->der->crl(self::NOW - Crl::DEFAULT_MAX_AGE - 86_400, self::NOW + 86_400);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/too old/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateAgeLimitIsConfigurableForAListWithANextUpdate(): void
    {
        $crl = $this->der->crl(self::NOW - 86_400, self::NOW + 86_400);

        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/too old/');
        (new Crl($this->asn1, maxAge: 3600))->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsAListThatIsNotYetValid(): void
    {
        $crl = $this->der->crl(1_900_000_000, 1_950_000_000);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not yet valid/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateToleratesClockSkew(): void
    {
        // A thisUpdate a minute ahead of the local clock is normal skew, not a fault.
        $crl = $this->der->crl(self::NOW + 60, self::NOW + 86_400);
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateRejectsMismatchedSignatureAlgorithms(): void
    {
        // RFC 5280 section 5.1.1.2: the inner AlgorithmIdentifier exists so the
        // algorithm is covered by the signature, and must equal the outer one.
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID))
                . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600)
                . $this->der->generalizedTime(1_900_000_000),
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/signature algorithms do not match/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsADeltaCrl(): void
    {
        // RFC 5280 section 5.2.4: a delta CRL lists only what changed since a base
        // list, so it is not a complete list.
        $crl = $this->crlWithExtension('2.5.29.27', $this->asn1->encodeInteger(3));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/delta CRL/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    /**
     * IssuingDistributionPoint flags that narrow a CRL to something else.
     *
     * @return array<string, array{string, string}>
     */
    public static function scopedCrlProvider(): array
    {
        return [
            'only some reasons' => ["\x83\x02\x05\xA0", 'subset of revocation reasons'],
            // An empty BIT STRING has the single content octet 0x00, as a BOOLEAN
            // carrying the DEFAULT FALSE does. onlySomeReasons has no default, so
            // present and empty covers no reason at all.
            'no reasons at all' => ["\x83\x01\x00", 'subset of revocation reasons'],
            'all reason flags clear' => ["\x83\x02\x00\x00", 'subset of revocation reasons'],
            'indirect CRL' => ["\x84\x01\xFF", 'another authority'],
            'attribute certificates only' => ["\x85\x01\xFF", 'attribute certificates'],
            'named distribution point' => ["\xA0\x01\x00", 'a named distribution point'],
        ];
    }

    #[DataProvider('scopedCrlProvider')]
    public function testValidateRejectsAScopedCrl(string $field, string $expected): void
    {
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence($field));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($expected, '/') . '/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    #[DataProvider('scopedCrlProvider')]
    public function testValidateRejectsANarrowingFieldPlacedAfterTheDistributionPoint(
        string $field,
        string $_expected,
    ): void {
        // The extension value is one IssuingDistributionPoint and nothing else.
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence('') . $field);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid CRL issuingDistributionPoint/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsAnUnknownCriticalExtension(): void
    {
        // RFC 5280 section 6.3.3 (a)(2): a critical extension the application cannot
        // process makes the list unusable for deciding a certificate's status.
        $crl = $this->crlWithExtension('1.3.6.1.4.1.99999.1', "\x05\x00");

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported critical CRL extension/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateAcceptsAKnownCriticalExtension(): void
    {
        // id-ce-cRLNumber is a counter and narrows nothing.
        $crl = $this->crlWithExtension('2.5.29.20', $this->asn1->encodeInteger(7));
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateRejectsADuplicateExtensionOid(): void
    {
        // RFC 5280 sections 4.2 and 5.2 admit one instance of each type, so a
        // duplicate is refused rather than collapsed to the last.
        $narrowing = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('2.5.29.28') . $this->asn1->encodeBoolean(true)
                . $this->asn1->encodeOctetString($this->asn1->encodeSequence("\x83\x02\x05\x40")),
        );
        $empty = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('2.5.29.28') . $this->asn1->encodeBoolean(true)
                . $this->asn1->encodeOctetString($this->asn1->encodeSequence('')),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Duplicate CRL extension: 2\.5\.29\.28/');
        $this->crl->validate($this->crlWithExtensions($narrowing . $empty), $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsACrlScopedToANamedDistributionPoint(): void
    {
        // RFC 5280 section 5.2.5 with the matching rule in section 6.3.3 (b)(1): a
        // named point restricts the list to the certificates whose own
        // cRLDistributionPoints name it, which is one shard of a partitioned list.
        $fullName = $this->asn1->encodeContext(0, $this->asn1->encodeContext(0, $this->asn1->encodeContext(
            6,
            'http://crl.example.com/p1.crl',
        )));
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence($fullName));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/scoped to a named distribution point/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    /**
     * IssuingDistributionPoint fields this reader cannot account for.
     *
     * The constructed forms are the primitive ones the DER encoding requires,
     * emitted as BER instead. Each names a narrowing that is refused in its
     * primitive form.
     *
     * @return array<string, array{string}>
     */
    public static function unsupportedScopeFieldProvider(): array
    {
        return [
            'constructed onlySomeReasons [3]' => ["\xA3\x04\x03\x02\x00\xA0"],
            'constructed indirectCRL [4]' => ["\xA4\x03\x01\x01\xFF"],
            'constructed onlyContainsAttributeCerts [5]' => ["\xA5\x03\x01\x01\xFF"],
            'a field the structure does not define' => ["\x86\x01\x00"],
        ];
    }

    #[DataProvider('unsupportedScopeFieldProvider')]
    public function testValidateRejectsAnUnsupportedScopeField(string $field): void
    {
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence($field));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported CRL issuingDistributionPoint field/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsACrlSignedByACertificateThatMayNotSignCrls(): void
    {
        // RFC 5280 section 6.3.3 (f), the counterpart of the id-kp-OCSPSigning check
        // on the OCSP side.
        $leaf = Authority::leaf();
        $crl = $this->der->crl(issuer: $leaf->subject($this->asn1), signer: $leaf);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not a certification authority/');
        $this->crl->validate($crl, $leaf->certDer, null, self::NOW);
    }

    public function testValidateAcceptsAnUnscopedIssuingDistributionPoint(): void
    {
        // onlyContainsUserCerts [1] FALSE narrows nothing.
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence("\x81\x01\x00"));
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    /**
     * The IssuingDistributionPoint fields that are BOOLEAN DEFAULT FALSE.
     *
     * @return array<string, array{string}>
     */
    public static function defaultFalseFieldProvider(): array
    {
        return [
            'onlyContainsUserCerts [1]' => ["\x81\x01\x00"],
            'onlyContainsCACerts [2]' => ["\x82\x01\x00"],
            'indirectCRL [4]' => ["\x84\x01\x00"],
            'onlyContainsAttributeCerts [5]' => ["\x85\x01\x00"],
        ];
    }

    #[DataProvider('defaultFalseFieldProvider')]
    public function testValidateAcceptsADefaultFalseScopeField(string $field): void
    {
        // These four carry the DEFAULT, so each is the same as its absence.
        // onlySomeReasons [3] does not share the exemption: its content octet is 0x00
        // too, and there it means the opposite.
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence($field));
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateAcceptsAPartitionCoveringTheSubject(): void
    {
        // RFC 5280 section 6.3.3 (b)(2): onlyContainsUserCerts and onlyContainsCACerts
        // split the issuer's certificates in two, each half answering for its own.
        $userCerts = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence("\x81\x01\xFF"));
        $caCerts = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence("\x82\x01\xFF"));

        $this->assertSame($userCerts, $this->crl->validate(
            $userCerts,
            $this->issuerDer,
            Authority::leaf()->certDer,
            self::NOW,
        ));
        $this->assertSame($caCerts, $this->crl->validate(
            $caCerts,
            $this->issuerDer,
            Authority::ocsp()->certDer,
            self::NOW,
        ));
    }

    public function testValidateRejectsACrlScopedToCaCertificatesForALeaf(): void
    {
        // An ARL: the same issuer, the same key, in date, correctly signed, and
        // listing only CA certificates, so it says nothing about the leaf.
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence("\x82\x01\xFF"));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/covers CA certificates only/');
        $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW);
    }

    public function testValidateRejectsACrlScopedToEndEntityCertificatesForACa(): void
    {
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence("\x81\x01\xFF"));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/covers end-entity certificates only/');
        $this->crl->validate($crl, $this->issuerDer, Authority::ocsp()->certDer, self::NOW);
    }

    public function testValidateRejectsAPartitionedCrlWithNoSubjectCertificate(): void
    {
        // Which half of the partition answers depends on the certificate, so with
        // none the list cannot be placed.
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeSequence("\x81\x01\xFF"));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/none was given to check it against/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsACrlThatRevokesTheSubject(): void
    {
        $subject = Authority::leaf()->certDer;
        $serial = (new Certificate($this->asn1))->fields($subject)['serial'];
        $crl = $this->crlWithRevocation($serial);

        $this->expectException(RevokedException::class);
        $this->expectExceptionMessageMatches('/is revoked/');
        $this->crl->validate($crl, $this->issuerDer, $subject, self::NOW);
    }

    public function testValidateAcceptsACrlThatRevokesAnotherCertificate(): void
    {
        $crl = $this->crlWithRevocation($this->asn1->encodeInteger(999_999));
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW));
    }

    public function testValidateReportsARevocationFoundAheadOfAMalformedEntry(): void
    {
        // Both faults refuse the list, under different verdicts, and revoked outranks
        // a structural fault in a later entry: Ltv\ValidationMaterial discards the
        // material for the whole certificate on a RevokedException and lets a second
        // mirror answer on a structural one.
        $subject = Authority::leaf()->certDer;
        $serial = (new Certificate($this->asn1))->fields($subject)['serial'];

        $crl = $this->crlWithEntries(
            $this->revocationEntry($serial)
                . $this->revocationEntry($this->asn1->encodeInteger(999_999), $this->asn1->encodeNull()),
        );

        $this->expectException(RevokedException::class);
        $this->expectExceptionMessageMatches('/is revoked/');
        $this->crl->validate($crl, $this->issuerDer, $subject, self::NOW);
    }

    public function testValidateRefusesAMalformedEntryAheadOfARevocation(): void
    {
        // The limit of the rule above: a fault ahead of the match leaves nothing
        // found, so the list is refused as malformed.
        $subject = Authority::leaf()->certDer;
        $serial = (new Certificate($this->asn1))->fields($subject)['serial'];

        $crl = $this->crlWithEntries(
            $this->revocationEntry($this->asn1->encodeInteger(999_999), $this->asn1->encodeNull())
                . $this->revocationEntry($serial),
        );

        try {
            $this->crl->validate($crl, $this->issuerDer, $subject, self::NOW);
            $this->fail('the malformed list was accepted');
        } catch (Exception $exception) {
            $this->assertNotInstanceOf(RevokedException::class, $exception);
            $this->assertMatchesRegularExpression(
                '/CRL entry extensions|Trailing bytes in a CRL revocation entry/',
                $exception->getMessage(),
            );
        }
    }

    public function testValidateRejectsAListFromAnAuthorityThatDidNotIssueTheSubject(): void
    {
        // RFC 5280 section 4.1.2.2: a serial number is unique only within an issuer,
        // so a list from an authority that did not issue the certificate indexes
        // nothing about it.
        $foreign = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ltv_cert.pem'));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/was not issued by the authority that issued the certificate/');
        $this->crl->validate($this->der->crl(), $this->issuerDer, $foreign, self::NOW);
    }

    public function testValidateRejectsAnUnknownCriticalEntryExtension(): void
    {
        // RFC 5280 section 5.3: a critical entry extension the application cannot
        // process makes the whole list unusable, as section 6.3.3 (a)(2) does for a
        // critical list extension.
        $crl = $this->crlWithRevocation(
            $this->asn1->encodeInteger(999_999),
            $this->der->extension('1.3.6.1.4.1.99999.7', "\x05\x00", true),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported critical CRL entry extension/');
        $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW);
    }

    public function testValidateWithoutASubjectStillAppliesTheEntryRules(): void
    {
        // $subjectDer gates the serial lookup alone. The entry walk and the RFC 5280
        // section 5.3 rule are about the list rather than about the certificate it was
        // fetched for, so they run either way.
        $crl = $this->crlWithRevocation(
            $this->asn1->encodeInteger(999_999),
            $this->der->extension('1.3.6.1.4.1.99999.7', "\x05\x00", true),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported critical CRL entry extension/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateWithoutASubjectStillBoundsEachEntry(): void
    {
        $crl = $this->crlWithRevocation($this->asn1->encodeInteger(999_999), entryTrailer: $this->asn1->encodeNull());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CRL entry extensions|Trailing bytes in a CRL revocation entry/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsARevocationDateThatIsNotATime(): void
    {
        // RFC 5280 section 5.1 types revocationDate a Time, so the field is decoded
        // rather than stepped over.
        $entry = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(999_999) . $this->asn1->encodeOctetString(\str_repeat('M', 64)),
        );

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->signatureAlgorithm()
                . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600)
                . $this->der->generalizedTime(1_900_000_000)
                . $this->asn1->encodeSequence($entry),
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid ASN.1 Time/');
        $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW);
    }

    public function testValidateAcceptsARecognisedCriticalEntryExtension(): void
    {
        // id-ce-cRLReason says why an entry is there, not that it is not there.
        $subject = Authority::leaf()->certDer;
        $crl = $this->crlWithRevocation(
            (new Certificate($this->asn1))->fields($subject)['serial'],
            $this->der->extension('2.5.29.21', $this->der->enumerated(1), true),
        );

        $this->expectException(RevokedException::class);
        $this->crl->validate($crl, $this->issuerDer, $subject, self::NOW);
    }

    public function testValidateAcceptsAnUnknownEntryExtensionThatIsNotCritical(): void
    {
        $crl = $this->crlWithRevocation(
            $this->asn1->encodeInteger(999_999),
            $this->der->extension('1.3.6.1.4.1.99999.7'),
        );

        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW));
    }

    public function testValidateReportsARevokedSubjectFromAnExpiredList(): void
    {
        // A list that has gone stale has still named the serial, so the revocation
        // is read before the freshness rule.
        $subject = Authority::leaf()->certDer;
        $crl = $this->crlWithRevocation(
            (new Certificate($this->asn1))->fields($subject)['serial'],
            '',
            self::NOW - 1800,
        );

        $this->expectException(RevokedException::class);
        $this->expectExceptionMessageMatches('/is revoked/');
        $this->crl->validate($crl, $this->issuerDer, $subject, self::NOW);
    }

    public function testValidateIgnoresRevocationEntriesWithoutASubject(): void
    {
        // No certificate to look up: the list is still validated as a list.
        $crl = $this->crlWithRevocation((new Certificate($this->asn1))->fields(Authority::leaf()->certDer)['serial']);
        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateRejectsARevocationEntryThatIsNotASequence(): void
    {
        $revoked = $this->asn1->encodeSequence($this->asn1->encodeInteger(7));

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->signatureAlgorithm()
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $this->der->generalizedTime(1_900_000_000)
            . $revoked,
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/revocation entry/');
        $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW);
    }

    public function testValidateRejectsAMalformedRevocationEntry(): void
    {
        $revoked = $this->asn1->encodeSequence($this->asn1->encodeSequence(
            $this->asn1->encodeOctetString('not a serial') . $this->der->generalizedTime(self::NOW - 3600),
        ));

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->signatureAlgorithm()
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $this->der->generalizedTime(1_900_000_000)
            . $revoked,
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/revocation entry/');
        $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW);
    }

    public function testValidateRejectsBytesAfterTheEntryExtensions(): void
    {
        // crlEntryExtensions is the last field of an entry (RFC 5280 section 5.1),
        // so nothing may follow it.
        $crl = $this->crlWithRevocation(
            $this->asn1->encodeInteger(99),
            $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier('2.5.29.21')
                    . $this->asn1->encodeOctetString($this->asn1->encodeInteger(1)),
            ),
            entryTrailer: $this->asn1->encodeOctetString(\str_repeat('X', 64)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes in a CRL revocation entry/');
        $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW);
    }

    public function testValidateAcceptsAUtcTimeValidityInterval(): void
    {
        // RFC 5280 section 5.1.2.4: a date before 2050 is carried as UTCTime.
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->signatureAlgorithm()
            . Authority::ocsp()->subject($this->asn1)
            . "\x17\x0D"
            . \gmdate('ymdHis', Der::RECENT_THIS_UPDATE)
            . 'Z'
            . "\x17\x0D"
            . \gmdate('ymdHis', 1_900_000_000)
            . 'Z',
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateAcceptsAV1ListWithoutAVersionField(): void
    {
        // version is OPTIONAL and absent in a v1 CRL.
        $tbs = $this->asn1->encodeSequence(
            $this->signatureAlgorithm() . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600),
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    public function testValidateReadsRevokedCertificatesInPlaceOfNextUpdate(): void
    {
        // revokedCertificates is a SEQUENCE, not a Time, so it is consumed at its own
        // position rather than read as a nextUpdate.
        $serial = (new Certificate($this->asn1))->fields(Authority::leaf()->certDer)['serial'];
        $revoked = $this->asn1->encodeSequence($this->asn1->encodeSequence(
            $serial . $this->der->generalizedTime(self::NOW - 3600),
        ));

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->signatureAlgorithm()
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $revoked,
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));

        $this->expectException(RevokedException::class);
        $this->crl->validate($crl, $this->issuerDer, Authority::leaf()->certDer, self::NOW);
    }

    /**
     * Malformed crlExtensions structures.
     *
     * @return array<string, array{callable(Asn1): string}>
     */
    public static function malformedExtensionsProvider(): array
    {
        return [
            'extensions not a sequence' => [static fn(Asn1 $asn1): string => $asn1->encodeInteger(1)],
            'extension not a sequence' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeInteger(1)),
            ],
            'extension type not an oid' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeSequence(
                    $asn1->encodeInteger(1) . $asn1->encodeOctetString('x'),
                )),
            ],
            'extension value not an octet string' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeSequence(
                    $asn1->encodeObjectIdentifier('2.5.29.20') . $asn1->encodeInteger(1),
                )),
            ],
        ];
    }

    /**
     * @param callable(Asn1): string $build
     */
    #[DataProvider('malformedExtensionsProvider')]
    public function testValidateRejectsMalformedExtensions(callable $build): void
    {
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->signatureAlgorithm()
                . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600)
                . $this->der->generalizedTime(1_900_000_000)
                . $this->asn1->encodeContext(0, $build($this->asn1)),
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CRL extension/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateRejectsAMalformedIssuingDistributionPoint(): void
    {
        $crl = $this->crlWithExtension('2.5.29.28', $this->asn1->encodeInteger(1));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/issuingDistributionPoint/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateAcceptsAnExtensionWithoutTheCriticalFlag(): void
    {
        // critical BOOLEAN DEFAULT FALSE is omitted when false, so the value follows
        // the type directly.
        $extension = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('2.5.29.20')
                . $this->asn1->encodeOctetString($this->asn1->encodeInteger(7)),
        );

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->signatureAlgorithm()
                . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600)
                . $this->der->generalizedTime(1_900_000_000)
                . $this->asn1->encodeContext(0, $this->asn1->encodeSequence($extension)),
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->assertSame($crl, $this->crl->validate($crl, $this->issuerDer, null, self::NOW));
    }

    /**
     * Build a signed CRL carrying one crlExtensions entry.
     */
    private function crlWithExtension(string $oid, string $value): string
    {
        return $this->crlWithExtensions($this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier($oid) . $this->asn1->encodeBoolean(true)
                . $this->asn1->encodeOctetString($value),
        ));
    }

    /**
     * Build a signed CRL carrying the given concatenated crlExtensions entries.
     */
    private function crlWithExtensions(string $extension): string
    {
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->signatureAlgorithm()
                . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600)
                . $this->der->generalizedTime(1_900_000_000)
                . $this->asn1->encodeContext(0, $this->asn1->encodeSequence($extension)),
        );

        return $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );
    }

    public function testValidateRefusesAnEmptyCrlExtensionsWrapper(): void
    {
        // An EXPLICIT tag wraps exactly one element (X.690 section 8.14), so A0 00 is
        // refused rather than read as an absent field, as
        // Ocsp\Client::optionalExtensions() refuses its own. openssl crl will not load
        // the result either.
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->signatureAlgorithm()
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $this->der->generalizedTime(1_900_000_000)
            . "\xA0\x00",
        );
        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Empty CRL crlExtensions/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    public function testValidateAcceptsAnEmptyExtensionsSequenceInsideTheWrapper(): void
    {
        // The control: a well-formed wrapper holding an Extensions SEQUENCE that
        // states nothing is DER and openssl crl loads it. Only the wrapper with no
        // element at all is refused.
        $this->assertNotSame('', $this->crl->validate($this->crlWithExtensions(''), $this->issuerDer, null, self::NOW));
    }

    /**
     * Build a signed CRL revoking one serial, given as a complete DER INTEGER.
     */
    private function crlWithRevocation(
        string $serial,
        string $entryExtensions = '',
        int $nextUpdate = 1_900_000_000,
        string $entryTrailer = '',
    ): string {
        $revoked = $this->asn1->encodeSequence($this->asn1->encodeSequence(
            $serial
            . $this->der->generalizedTime(self::NOW - 3600)
            . ($entryExtensions === '' ? '' : $this->asn1->encodeSequence($entryExtensions))
            . $entryTrailer,
        ));

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->signatureAlgorithm()
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $this->der->generalizedTime($nextUpdate)
            . $revoked,
        );

        return $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );
    }

    /**
     * Build one revocation entry, given the serial as a complete DER INTEGER.
     */
    private function revocationEntry(string $serial, string $trailer = ''): string
    {
        return $this->asn1->encodeSequence($serial . $this->der->generalizedTime(self::NOW - 3600) . $trailer);
    }

    /**
     * Build a signed CRL over ready revocation entries.
     */
    private function crlWithEntries(string $entries): string
    {
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->signatureAlgorithm()
                . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600)
                . $this->der->generalizedTime(1_900_000_000)
                . $this->asn1->encodeSequence($entries),
        );

        return $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );
    }

    /**
     * Build a signed CRL whose TBSCertList tail is preceded by an unrecognised field.
     *
     * RFC 5280 section 5.1.2 gives TBSCertList a closed field list with no extension
     * point, so a [5] element here is a structure the reader has to refuse.
     */
    private function crlWithFieldBeforeTheTail(string $tail): string
    {
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->signatureAlgorithm()
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $this->der->generalizedTime(1_900_000_000)
            . $this->asn1->encodeContext(5, '')
            . $tail,
        );

        return $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );
    }

    /**
     * TBSCertList tails whose acceptance rule an unread field ahead of them disabled.
     *
     * @return array<string, array{string}>
     */
    public static function shiftedTbsCertListTailProvider(): array
    {
        $asn1 = new Asn1();

        $indirect = $asn1->encodeContext(
            0,
            $asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('2.5.29.28') . $asn1->encodeBoolean(true)
                    . $asn1->encodeOctetString($asn1->encodeSequence("\x84\x01\xFF")),
            ),
        );

        $delta = $asn1->encodeContext(
            0,
            $asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('2.5.29.27') . $asn1->encodeBoolean(true)
                    . $asn1->encodeOctetString($asn1->encodeInteger(3)),
            ),
        );

        return [
            'an issuingDistributionPoint marking the list indirect' => [$indirect],
            'a deltaCRLIndicator' => [$delta],
        ];
    }

    #[DataProvider('shiftedTbsCertListTailProvider')]
    public function testValidateRefusesAFieldAheadOfTheTbsCertListTail(string $tail): void
    {
        // nextUpdate, revokedCertificates and crlExtensions are each consumed at
        // their own position, so an element the walk does not recognise is refused
        // rather than absorbing the look-ahead.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TBSCertList field after thisUpdate/');
        $this->crl->validate($this->crlWithFieldBeforeTheTail($tail), $this->issuerDer, null, self::NOW);
    }

    public function testValidateRefusesARevokedListHiddenBehindAnUnreadField(): void
    {
        // The case the class docblock states: a CRL that revokes the signer is
        // reported as such rather than embedded as that signer's own validation
        // material, wherever the revokedCertificates field sits.
        $serial = (new Certificate($this->asn1))->fields(Authority::leaf()->certDer)['serial'];
        $revoked = $this->asn1->encodeSequence($this->asn1->encodeSequence(
            $serial . $this->der->generalizedTime(self::NOW - 3600),
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TBSCertList field after thisUpdate/');
        $this->crl->validate(
            $this->crlWithFieldBeforeTheTail($revoked),
            $this->issuerDer,
            Authority::leaf()->certDer,
            self::NOW,
        );
    }

    public function testValidateRefusesBytesAfterTheTbsCertListExtensions(): void
    {
        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->signatureAlgorithm()
                . Authority::ocsp()->subject($this->asn1)
                . $this->der->generalizedTime(self::NOW - 3600)
                . $this->der->generalizedTime(1_900_000_000)
                . $this->asn1->encodeContext(
                    0,
                    $this->asn1->encodeSequence(
                        $this->asn1->encodeObjectIdentifier('2.5.29.20')
                            . $this->asn1->encodeOctetString($this->asn1->encodeInteger(7)),
                    ),
                )
                . $this->asn1->encodeOctetString('trailing'),
        );

        $crl = $this->asn1->encodeSequence(
            $tbs . $this->signatureAlgorithm() . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the TBSCertList extensions/');
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedCrlProvider(): array
    {
        $asn1 = new Asn1();

        return [
            'trailing bytes after the signature' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($asn1->encodeSequence('') . $asn1->encodeSequence(''))
                        . $asn1->encodeSequence('')
                        . "\x03\x02\x00\x01"
                        . $asn1->encodeInteger(1),
                ),
            ],
            'tbs not a sequence' => [$asn1->encodeSequence($asn1->encodeInteger(1))],
            'signature not a bit string' => [
                $asn1->encodeSequence($asn1->encodeSequence('') . $asn1->encodeSequence('') . $asn1->encodeInteger(1)),
            ],
            'issuer not a name' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($asn1->encodeSequence('') . $asn1->encodeInteger(1))
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
            ],
            'signature algorithm not a sequence' => [
                $asn1->encodeSequence(
                    $asn1->encodeSequence($asn1->encodeInteger(1) . $asn1->encodeInteger(2))
                    . $asn1->encodeSequence('')
                    . "\x03\x02\x00\x01",
                ),
            ],
        ];
    }

    #[DataProvider('malformedCrlProvider')]
    public function testValidateRejectsMalformedStructures(string $crl): void
    {
        $this->expectException(Exception::class);
        $this->crl->validate($crl, $this->issuerDer, null, self::NOW);
    }

    /**
     * The sha256WithRSAEncryption AlgorithmIdentifier the fixtures use.
     */
    private function signatureAlgorithm(): string
    {
        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID) . $this->asn1->encodeNull(),
        );
    }
}
