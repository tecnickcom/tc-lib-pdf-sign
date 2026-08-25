<?php

declare(strict_types=1);

/**
 * SigningRequestTest.php
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
use Com\Tecnick\Pdf\Sign\Cms\SigningRequest;
use Com\Tecnick\Pdf\Sign\DigestAlgorithm;
use Com\Tecnick\Pdf\Sign\Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Credentials;

/**
 * CMS SigningRequest Test
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(SigningRequest::class)]
final class SigningRequestTest extends TestCase
{
    private const SIGNING_TIME = 1_700_000_000;

    /**
     * CAdES signature-policy-identifier, the ICP-Brasil case from the request.
     */
    private const OID_SIGNATURE_POLICY = '1.2.840.113549.1.9.16.2.15';

    private Asn1 $asn1;

    private string $certDer;

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->certDer = $this->makeCertificateDer();
    }

    public function testConstructorNormalisesTheDigestAlgorithm(): void
    {
        $request = new SigningRequest(
            \hash('sha384', 'content', true),
            $this->certDer,
            DigestAlgorithm::Sha384,
            self::SIGNING_TIME,
        );

        $this->assertSame('sha384', $request->digestAlgorithm);
        $this->assertSame(\hash('sha384', 'content', true), $request->messageDigest);
        $this->assertSame($this->certDer, $request->signerCertDer);
        $this->assertSame(self::SIGNING_TIME, $request->signingTime);
        $this->assertTrue($request->includeSigningTime);
        $this->assertSame([], $request->extraSignedAttributes);
    }

    public function testSignerCertPemWrapsTheDer(): void
    {
        $request = $this->makeRequest();
        $pem = $request->signerCertPem();

        $this->assertStringStartsWith("-----BEGIN CERTIFICATE-----\n", $pem);
        $this->assertStringEndsWith("-----END CERTIFICATE-----\n", $pem);
        $this->assertNotFalse(\openssl_pkey_get_public($pem));
    }

    public function testConstructorRejectsADigestOfTheWrongLength(): void
    {
        // A digest of the wrong length is a digest of something else.
        $this->expectException(Exception::class);
        new SigningRequest(\hash('sha256', 'content', true), $this->certDer, 'sha512', self::SIGNING_TIME);
    }

    public function testConstructorRejectsAnUnsupportedDigest(): void
    {
        $this->expectException(Exception::class);
        new SigningRequest(\hash('md5', 'content', true), $this->certDer, 'md5', self::SIGNING_TIME);
    }

    public function testConstructorRejectsAnUnreadableCertificate(): void
    {
        $this->expectException(Exception::class);
        new SigningRequest(\hash('sha256', 'content', true), 'not a certificate', 'sha256', self::SIGNING_TIME);
    }

    public function testConstructorRejectsANegativeSigningTime(): void
    {
        $this->expectException(Exception::class);
        new SigningRequest(\hash('sha256', 'content', true), $this->certDer, 'sha256', -1);
    }

    public function testConstructorRejectsASigningTimePastTheEndOfDerTime(): void
    {
        // X.690 section 11.7 fixes the GeneralizedTime year at four digits, so past
        // 9999 gmdate() emits a five-digit year.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signing time/');
        new SigningRequest(
            \hash('sha256', 'content', true),
            $this->certDer,
            'sha256',
            SigningRequest::MAX_SIGNING_TIME + 1,
        );
    }

    public function testConstructorAcceptsTheLastRepresentableSigningTime(): void
    {
        $request = new SigningRequest(
            \hash('sha256', 'content', true),
            $this->certDer,
            'sha256',
            SigningRequest::MAX_SIGNING_TIME,
        );

        // The attribute the builder derives is a well-formed GeneralizedTime.
        $this->assertStringContainsString(
            "\x18\x0F99991231235959Z",
            (new Builder($this->asn1))->signaturePayload($request),
        );
    }

    public function testConstructorAcceptsAnExtraSignedAttribute(): void
    {
        $value = $this->asn1->encodeObjectIdentifier('2.16.76.1.7.1.1.2.3');
        $request = $this->makeRequest([self::OID_SIGNATURE_POLICY => $value]);

        $this->assertSame([self::OID_SIGNATURE_POLICY => $value], $request->extraSignedAttributes);
    }

    public function testConstructorRejectsAReservedExtraAttributeOid(): void
    {
        // A second message-digest attribute makes the CMS ambiguous (RFC 5652 section 5.3).
        $this->expectException(Exception::class);
        $this->makeRequest(['1.2.840.113549.1.9.4' => $this->asn1->encodeOctetString('other digest')]);
    }

    public function testConstructorRejectsAReservedSigningCertificateOid(): void
    {
        $this->expectException(Exception::class);
        $this->makeRequest(['1.2.840.113549.1.9.16.2.47' => $this->asn1->encodeOctetString('other hash')]);
    }

    public function testConstructorRejectsAMalformedExtraAttributeOid(): void
    {
        $this->expectException(Exception::class);
        $this->makeRequest(['not.an.oid' => $this->asn1->encodeNull()]);
    }

    public function testConstructorRejectsANonNumericExtraAttributeKey(): void
    {
        $this->expectException(Exception::class);
        $this->makeRequest([7 => $this->asn1->encodeNull()]);
    }

    public function testConstructorRejectsAnExtraAttributeValueWithTrailingBytes(): void
    {
        $this->expectException(Exception::class);
        $this->makeRequest([self::OID_SIGNATURE_POLICY => $this->asn1->encodeNull() . "\x00"]);
    }

    public function testConstructorRejectsAMalformedExtraAttributeValue(): void
    {
        $this->expectException(Exception::class);
        $this->makeRequest([self::OID_SIGNATURE_POLICY => "\x30\x7F"]);
    }

    public function testConstructorRejectsAnEmptyExtraAttributeValue(): void
    {
        $this->expectException(Exception::class);
        $this->makeRequest([self::OID_SIGNATURE_POLICY => '']);
    }

    public function testToArrayAndFromArrayRoundTrip(): void
    {
        $value = $this->asn1->encodeObjectIdentifier('2.16.76.1.7.1.1.2.3');
        $request = new SigningRequest(
            \hash('sha512', 'content', true),
            $this->certDer,
            'sha512',
            self::SIGNING_TIME,
            false,
            [self::OID_SIGNATURE_POLICY => $value],
        );

        // The state survives a JSON hop, which is the remote signing round trip.
        $encoded = \json_encode($request->toArray());
        $this->assertIsString($encoded);
        /** @var mixed $decoded */
        $decoded = \json_decode($encoded, true);
        $this->assertIsArray($decoded);

        $restored = SigningRequest::fromArray($decoded);

        $this->assertSame($request->messageDigest, $restored->messageDigest);
        $this->assertSame($request->signerCertDer, $restored->signerCertDer);
        $this->assertSame($request->digestAlgorithm, $restored->digestAlgorithm);
        $this->assertSame($request->signingTime, $restored->signingTime);
        $this->assertSame($request->includeSigningTime, $restored->includeSigningTime);
        $this->assertSame($request->extraSignedAttributes, $restored->extraSignedAttributes);
    }

    public function testMacProtectedRoundTrip(): void
    {
        $request = $this->makeRequest();
        $state = $request->toArray('secret');

        $this->assertArrayHasKey('mac', $state);
        $this->assertSame($request->messageDigest, SigningRequest::fromArray($state, 'secret')->messageDigest);
    }

    public function testUnprotectedExportCarriesNoMac(): void
    {
        $this->assertArrayNotHasKey('mac', $this->makeRequest()->toArray());
    }

    public function testMacRejectsASubstitutedMessageDigest(): void
    {
        // Re-validating catches a malformed payload; only the MAC catches a payload
        // edited into a different valid request.
        $state = $this->makeRequest()->toArray('secret');
        $state['message_digest'] = \base64_encode(\hash('sha256', 'another document', true));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/altered or signed with another key/');
        SigningRequest::fromArray($state, 'secret');
    }

    public function testMacRejectsAnotherKey(): void
    {
        $this->expectException(Exception::class);
        SigningRequest::fromArray($this->makeRequest()->toArray('secret'), 'another secret');
    }

    public function testMacRejectsAMissingMac(): void
    {
        $this->expectException(Exception::class);
        SigningRequest::fromArray($this->makeRequest()->toArray(), 'secret');
    }

    public function testMacIsIndependentOfKeyOrder(): void
    {
        $state = $this->makeRequest()->toArray('secret');
        $shuffled = \array_reverse($state, true);

        $this->assertNotSame(\array_keys($state), \array_keys($shuffled));
        $this->assertInstanceOf(SigningRequest::class, SigningRequest::fromArray($shuffled, 'secret'));
    }

    public function testMacIsIndependentOfTheAttributeMapOrder(): void
    {
        // The attribute map is sorted too, so a host that rebuilds it in another
        // order is carrying the same request.
        $request = $this->makeRequest([
            '2.16.76.1.7.1.1.2.3' => $this->asn1->encodeOctetString('a'),
            '1.2.840.113549.1.9.16.2.15' => $this->asn1->encodeOctetString('b'),
        ]);

        $state = $request->toArray('secret');
        $state['extra_signed_attributes'] = \array_reverse($state['extra_signed_attributes'], true);

        $this->assertInstanceOf(SigningRequest::class, SigningRequest::fromArray($state, 'secret'));
    }

    public function testMacIsIndependentOfTheOrderOfNumericStringOids(): void
    {
        // A two-arc OID is a numeric string, and under the default SORT_REGULAR PHP
        // compares two of those as numbers: "1.2" and "1.20" come out equal, leaving
        // the order to insertion.
        $one = $this->asn1->encodeOctetString('a');
        $two = $this->asn1->encodeOctetString('b');

        $first = $this->makeRequest(['1.2' => $one, '1.20' => $two])->toArray('secret');
        $second = $this->makeRequest(['1.20' => $two, '1.2' => $one])->toArray('secret');

        $this->assertArrayHasKey('mac', $first);
        $this->assertArrayHasKey('mac', $second);
        $this->assertSame($first['mac'] ?? '', $second['mac'] ?? '');
        $this->assertInstanceOf(SigningRequest::class, SigningRequest::fromArray($second, 'secret'));
    }

    public function testMacRejectsAnEmptyKey(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/MAC key is empty/');
        $this->makeRequest()->toArray('');
    }

    public function testMacRejectsAFieldThatIsNotUtf8(): void
    {
        // The MAC is computed over the payload as received, so json_encode() is
        // handed the transport's bytes. A string that is not UTF-8 makes it throw a
        // JsonException, which is translated rather than left to escape.
        $state = $this->makeRequest()->toArray('secret');
        $state['digest_algorithm'] = "sha256\xC3\x28";

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/state cannot be encoded/');
        SigningRequest::fromArray($state, 'secret');
    }

    public function testMacRejectsAFieldThatIsNotFinite(): void
    {
        // The other value json_encode() refuses: a JSON number too large for a PHP
        // integer decodes to INF.
        $state = $this->makeRequest()->toArray('secret');
        $state['signing_time'] = INF;

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/state cannot be encoded/');
        SigningRequest::fromArray($state, 'secret');
    }

    public function testMacRejectsAnAddedFieldThatIsNotUtf8(): void
    {
        // The MAC covers the state as received, so a field the request does not have
        // reaches json_encode() too.
        $state = $this->makeRequest()->toArray('secret');
        $state['added'] = "\xED\xA0\x80";

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/state cannot be encoded/');
        SigningRequest::fromArray($state, 'secret');
    }

    public function testConstructorRejectsACertificateWithTrailingBytes(): void
    {
        // openssl_pkey_get_public() reads the first element and ignores the rest, so
        // trailing bytes are refused here.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid DER for signer certificate/');
        new SigningRequest(\hash('sha256', 'content', true), $this->certDer . 'TRAILING');
    }

    public function testConstructorRejectsAWellFormedDerThatIsNotACertificate(): void
    {
        // Passes the structural check, so only OpenSSL can reject it.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unreadable signer certificate/');
        new SigningRequest(\hash('sha256', 'content', true), $this->asn1->encodeSequence("\x02\x01\x01"));
    }

    public function testConstructorRejectsAnEmptyCertificate(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Empty signer certificate/');
        new SigningRequest(\hash('sha256', 'content', true), '');
    }

    public function testConstructorRejectsACertificateOnlyThisLibraryRefuses(): void
    {
        // RFC 5280 section 4.1.1.2 requires the TBSCertificate signature field and
        // the outer signatureAlgorithm to carry the same identifier, which OpenSSL
        // does not weigh at read time. The library's own parse runs at construction,
        // so the refusal lands before an external signer has spent a signature.
        $patched = $this->certificateWithMismatchedAlgorithms();
        $this->assertNotFalse(\openssl_pkey_get_public(Certificate::derToPem($patched)));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signer certificate/');
        new SigningRequest(\hash('sha256', 'content', true), $patched);
    }

    public function testConstructorRejectsAnExtraAttributeValueThatIsNotAString(): void
    {
        // Held here as well as in fromArray(): a value that is not a string would
        // reach Asn1::readTlv() as a TypeError.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signed attribute value: 1\.2\.3/');

        // Typed loosely on purpose: a map whose values are not the strings the
        // declared shape promises.
        /** @var array<array-key, string> $attributes */
        $attributes = ['1.2.3' => 42];
        new SigningRequest(\hash('sha256', 'content', true), $this->certDer, 'sha256', 0, true, $attributes);
    }

    /**
     * @return list<array{string}>
     */
    public static function encoderRejectedOidProvider(): array
    {
        // Accepted by a looser pattern and refused by the encoder, so validating with
        // the encoder itself refuses them at construction rather than at the first
        // payload call.
        return [['1.99.1'], ['0.40.1'], ['1.02.3'], ['3.1.1'], ['1']];
    }

    #[DataProvider('encoderRejectedOidProvider')]
    public function testConstructorRejectsAnOidTheEncoderCannotEmit(string $oid): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signed attribute OID/');
        $this->makeRequest([$oid => "\x05\x00"]);
    }

    public function testFromArrayRejectsAMissingField(): void
    {
        $state = $this->makeRequest()->toArray();
        unset($state['signing_time']);

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRejectsANonBase64BinaryField(): void
    {
        $state = $this->makeRequest()->toArray();
        $state['message_digest'] = '!!! not base64 !!!';

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRejectsANonStringDigestAlgorithm(): void
    {
        $state = $this->makeRequest()->toArray();
        $state['digest_algorithm'] = 256;

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRejectsANonIntegerSigningTime(): void
    {
        $state = $this->makeRequest()->toArray();
        $state['signing_time'] = '1700000000';

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRejectsANonBooleanIncludeSigningTime(): void
    {
        $state = $this->makeRequest()->toArray();
        $state['include_signing_time'] = 1;

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRejectsANonArrayExtraAttributeMap(): void
    {
        $state = $this->makeRequest()->toArray();
        $state['extra_signed_attributes'] = 'none';

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRejectsANonStringExtraAttributeValue(): void
    {
        $state = $this->makeRequest()->toArray();
        $state['extra_signed_attributes'] = [self::OID_SIGNATURE_POLICY => 42];

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRejectsANonBase64ExtraAttributeValue(): void
    {
        $state = $this->makeRequest()->toArray();
        $state['extra_signed_attributes'] = [self::OID_SIGNATURE_POLICY => '!!! not base64 !!!'];

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    public function testFromArrayRevalidatesATamperedPayload(): void
    {
        $state = $this->makeRequest()->toArray();
        // A digest truncated in transit does not match its algorithm.
        $state['message_digest'] = \base64_encode(\substr(\hash('sha256', 'content', true), 0, 16));

        $this->expectException(Exception::class);
        SigningRequest::fromArray($state);
    }

    /**
     * @param array<array-key, string> $extraSignedAttributes
     */
    private function makeRequest(array $extraSignedAttributes = []): SigningRequest
    {
        return new SigningRequest(
            \hash('sha256', 'content', true),
            $this->certDer,
            'sha256',
            self::SIGNING_TIME,
            true,
            $extraSignedAttributes,
        );
    }

    /**
     * The fixture certificate with its outer signatureAlgorithm OID changed from
     * sha256WithRSAEncryption to sha384WithRSAEncryption.
     *
     * The two OIDs are the same length, so no length octet moves and the result is
     * still a certificate OpenSSL reads. Only the outer identifier is replaced: the
     * TBSCertificate carries the same octets, and replacing both would leave the two
     * fields agreeing again.
     */
    private function certificateWithMismatchedAlgorithms(): string
    {
        $offset = 0;
        $certificate = $this->asn1->readTlv($this->certDer, $offset);
        $header = \strlen($this->certDer) - \strlen($certificate['value']);

        $inner = 0;
        $this->asn1->readTlv($certificate['value'], $inner);
        $start = $header + $inner;
        $algorithm = $this->asn1->readTlv($certificate['value'], $inner);

        $patched = \str_replace(
            (string) \hex2bin('06092a864886f70d01010b'),
            (string) \hex2bin('06092a864886f70d01010c'),
            $algorithm['raw'],
        );

        return \substr_replace($this->certDer, $patched, $start, \strlen($algorithm['raw']));
    }

    /**
     * The DER of a self-signed certificate.
     *
     * Memoised by the fixture, so the key is generated once per process rather
     * than once per test.
     */
    private function makeCertificateDer(): string
    {
        $credential = Credentials::make();
        if ($credential === null) {
            $this->markTestSkipped('RSA key generation is not available');
        }

        return $credential['cert_der'];
    }
}
