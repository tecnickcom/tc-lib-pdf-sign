<?php

declare(strict_types=1);

/**
 * ClientTest.php
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 *
 * This file is part of tc-lib-pdf-sign software library.
 */

namespace Test\Timestamp;

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Cms\SignedDataVerifier;
use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Timestamp\Client;
use Com\Tecnick\Pdf\Sign\Timestamp\Config;
use Com\Tecnick\Pdf\Sign\Timestamp\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Der;

/**
 * Timestamp Client Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Client::class)]
#[CoversClass(Request::class)]
final class ClientTest extends TestCase
{
    /**
     * The instant every fixture token is stamped at, and the one the codec checks
     * genTime against. Fixed so the suite does not depend on the wall clock.
     */
    private const NOW = 1_700_000_000;

    private Asn1 $asn1;

    private Der $der;

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->der = new Der($this->asn1);
    }

    private function client(bool $nonce = false, string $policyOid = '', string $hash = 'sha256'): Client
    {
        return new Client(new Config(
            host: 'https://tsa.example.org',
            hashAlgorithm: $hash,
            policyOid: $policyOid,
            nonceEnabled: $nonce,
        ));
    }

    /**
     * Build the token a conforming TSA would return for a request.
     *
     * @param list<string> $certsDer
     */
    private function tokenFor(Request $request, array $certsDer = []): string
    {
        return $this->der->signedTimestampToken(
            $this->der->tstInfo($request->imprint, $request->hashOid, $request->nonce),
            $certsDer,
        );
    }

    public function testHashAlgorithmOid(): void
    {
        $client = $this->client();
        $this->assertSame('2.16.840.1.101.3.4.2.1', $client->hashAlgorithmOid('sha256'));
        $this->assertSame('2.16.840.1.101.3.4.2.2', $client->hashAlgorithmOid('sha384'));
        $this->assertSame('2.16.840.1.101.3.4.2.3', $client->hashAlgorithmOid('sha512'));
    }

    public function testHashAlgorithmOidRejectsUnknown(): void
    {
        $this->expectException(Exception::class);
        $this->client()->hashAlgorithmOid('sha1');
    }

    public function testBuildRequestStructure(): void
    {
        $request = $this->client()->buildRequest('payload');
        $this->assertSame(\hash('sha256', 'payload', true), $request->imprint);
        $this->assertSame('2.16.840.1.101.3.4.2.1', $request->hashOid);
        $this->assertSame('', $request->nonce);

        $offset = 0;
        $root = $this->asn1->readTlv($request->der, $offset);
        $this->assertSame(0x30, $root['tag']);
        $this->assertSame(\strlen($request->der), $offset);

        $inner = 0;
        $version = $this->asn1->readTlv($root['value'], $inner);
        $this->assertSame(0x02, $version['tag']);
        $this->assertSame(1, $this->asn1->decodeInteger($version['value']));

        $messageImprint = $this->asn1->readTlv($root['value'], $inner);
        $this->assertSame(0x30, $messageImprint['tag']);

        $certReq = $this->asn1->readTlv($root['value'], $inner);
        $this->assertSame(0x01, $certReq['tag']);
        $this->assertSame("\xFF", $certReq['value']);
        // Nothing follows certReq when no policy and no nonce are present.
        $this->assertSame(\strlen($root['value']), $inner);

        // The message imprint carries the SHA-256 digest of the input.
        $miOffset = 0;
        $algId = $this->asn1->readTlv($messageImprint['value'], $miOffset);
        $this->assertSame(0x30, $algId['tag']);
        $digest = $this->asn1->readTlv($messageImprint['value'], $miOffset);
        $this->assertSame(0x04, $digest['tag']);
        $this->assertSame(\hash('sha256', 'payload', true), $digest['value']);
    }

    public function testMessageImprintOmitsAlgorithmParameters(): void
    {
        // RFC 5754 section 2: SHA-2 AlgorithmIdentifiers are generated with the
        // parameters absent, matching what Cms\Builder emits.
        $request = $this->client()->buildRequest('payload');

        $offset = 0;
        $root = $this->asn1->readTlv($request->der, $offset);
        $inner = 0;
        $this->asn1->readTlv($root['value'], $inner);
        $messageImprint = $this->asn1->readTlv($root['value'], $inner);

        $miOffset = 0;
        $algId = $this->asn1->readTlv($messageImprint['value'], $miOffset);

        $algOffset = 0;
        $this->asn1->readTlv($algId['value'], $algOffset);
        $this->assertSame(\strlen($algId['value']), $algOffset, 'AlgorithmIdentifier carries parameters');
    }

    public function testBuildRequestIncludesPolicyOid(): void
    {
        $request = $this->client(policyOid: '1.2.3.4')->buildRequest('x');

        $offset = 0;
        $root = $this->asn1->readTlv($request->der, $offset);
        $inner = 0;
        $this->asn1->readTlv($root['value'], $inner); // version
        $this->asn1->readTlv($root['value'], $inner); // messageImprint

        $policy = $this->asn1->readTlv($root['value'], $inner);
        $this->assertSame(0x06, $policy['tag']);
        $this->assertSame($this->asn1->encodeObjectIdentifier('1.2.3.4'), $policy['raw']);
    }

    public function testBuildRequestIncludesNonce(): void
    {
        $request = $this->client(nonce: true)->buildRequest('x');
        $this->assertNotSame('', $request->nonce);

        $offset = 0;
        $root = $this->asn1->readTlv($request->der, $offset);
        $inner = 0;
        $this->asn1->readTlv($root['value'], $inner); // version
        $this->asn1->readTlv($root['value'], $inner); // messageImprint

        $nonce = $this->asn1->readTlv($root['value'], $inner);
        $this->assertSame(0x02, $nonce['tag']);
        $this->assertSame($request->nonce, $nonce['raw']);

        $certReq = $this->asn1->readTlv($root['value'], $inner);
        $this->assertSame(0x01, $certReq['tag']);
    }

    public function testBuildRequestNoncesDiffer(): void
    {
        $client = $this->client(nonce: true);
        $this->assertNotSame($client->buildRequest('x')->nonce, $client->buildRequest('x')->nonce);
    }

    public function testBuildRequestNonceCarriesAtLeastSixtyFourBits(): void
    {
        // RFC 3161 section 2.4.1 asks for at least 64 bits, which random_int(1,
        // PHP_INT_MAX) gives 63 of on a 64-bit build and 31 of on a 32-bit one.
        $client = $this->client(nonce: true);

        // The draw is eight octets and the encoding is the minimal DER INTEGER over
        // them, so the content is nine octets when the leading one has its top bit
        // set, eight when it does not, and seven when it is zero and DER trims it.
        // Both of the first two widths occur in 128 draws except with probability
        // around 2^-64.
        $widths = [];
        for ($run = 0; $run < 128; ++$run) {
            $nonce = $client->buildRequest('x')->nonce;
            $this->assertSame(0x02, \ord($nonce[0]));

            $magnitude = \substr($nonce, 2);
            $this->assertSame(
                $nonce,
                $this->asn1->encodeIntegerBytes($magnitude),
                'nonce is not a minimal DER INTEGER: ' . \bin2hex($nonce),
            );
            $this->assertLessThanOrEqual(9, \strlen($magnitude), 'nonce wider than the draw: ' . \bin2hex($nonce));

            $widths[\strlen($magnitude)] = true;
        }

        $this->assertArrayHasKey(9, $widths, 'no nonce with the top bit of the draw set');
        $this->assertArrayHasKey(8, $widths, 'no nonce with the top bit of the draw clear');
    }

    /**
     * @return list<array{int<0, max>}>
     */
    public static function acceptedStatusProvider(): array
    {
        return [[0], [1]];
    }

    /**
     * @param int<0, max> $status
     */
    #[DataProvider('acceptedStatusProvider')]
    public function testParseResponseReturnsMatchingToken(int $status): void
    {
        $client = $this->client(nonce: true);
        $request = $client->buildRequest('payload');
        $token = $this->tokenFor($request);

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse($status, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseRejectsACriticalTstInfoExtension(): void
    {
        // This codec reads no TSTInfo extension, so a critical one is refused, as the
        // OCSP and CRL readers refuse theirs.
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            $request->imprint,
            $request->hashOid,
            $request->nonce,
            self::NOW,
            $this->der->extension('1.3.6.1.4.1.99999.3', "\x05\x00", true),
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported critical TSA token extension/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    /**
     * Fields standing between genTime and extensions [1] that RFC 3161 section 2.4.2
     * does not put there, or does not put there twice or in that order.
     *
     * @return array<string, array{string}>
     */
    public static function malformedTstInfoTailProvider(): array
    {
        $asn1 = new Asn1();
        $marker = $asn1->encodeOctetString(\str_repeat('P', 64));

        return [
            'chosen bytes after genTime' => [$marker],
            'chosen bytes after the nonce' => [$asn1->encodeInteger(7) . $marker],
            'a second nonce' => [$asn1->encodeInteger(7) . $asn1->encodeInteger(9)],
            'accuracy after the nonce' => [
                $asn1->encodeInteger(7) . $asn1->encodeSequence($asn1->encodeInteger(1)),
            ],
            'tsa [0] before the nonce' => [
                $asn1->encodeContext(0, $asn1->encodeContext(4, $asn1->encodeSequence(''))) . $asn1->encodeInteger(7),
            ],
        ];
    }

    /**
     * Tail fields whose tag ranks correctly and whose content is not the field.
     *
     * @return array<string, array{string, string}>
     */
    public static function malformedTstInfoFieldProvider(): array
    {
        $asn1 = new Asn1();
        $marker = \str_repeat('P', 64);

        return [
            'ordering of 64 octets' => ["\x01" . $asn1->encodeLength(64) . $marker, 'Invalid TSA token ordering'],
            'ordering of no octets' => ["\x01\x00", 'Invalid TSA token ordering'],
            'accuracy of chosen bytes' => [
                $asn1->encodeSequence($asn1->encodeOctetString($marker)),
                'Invalid TSA token accuracy field',
            ],
            'accuracy micros before millis' => [
                $asn1->encodeSequence("\x81\x01\x01\x80\x01\x01"),
                'Invalid TSA token accuracy field',
            ],
            'accuracy seconds not minimal' => [
                $asn1->encodeSequence("\x02\x02\x00\x01"),
                'Non-minimal ASN.1 integer encoding',
            ],
            'tsa [0] of chosen bytes' => [
                $asn1->encodeContext(0, $marker),
                'Malformed ASN.1 length',
            ],
            'tsa [0] of two elements' => [
                $asn1->encodeContext(0, $asn1->encodeNull() . $asn1->encodeNull()),
                'Invalid TSA token tsa field',
            ],
            'tsa [0] empty' => [$asn1->encodeContext(0, ''), 'Empty TSA token tsa field'],
        ];
    }

    #[DataProvider('malformedTstInfoFieldProvider')]
    public function testParseResponseReadsTheTstInfoTailFieldsItRanks(string $tail, string $message): void
    {
        // Each field is read as well as ranked, so its content is held to the shape
        // RFC 3161 section 2.4.2 gives it. OpenSSL decodes none of these.
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            $request->imprint,
            $request->hashOid,
            $tail,
            self::NOW,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    #[DataProvider('malformedTstInfoTailProvider')]
    public function testParseResponseHoldsTheTstInfoTailToTheRfcGrammar(string $tail): void
    {
        // accuracy, ordering, nonce and tsa [0] stand there, each at most once and in
        // that order, so a repeat or a field out of order is refused.
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            $request->imprint,
            $request->hashOid,
            $tail,
            self::NOW,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TSA token field after the genTime/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseAcceptsTheTstInfoTailInTheRfcOrder(): void
    {
        // The control for the rules above: every optional field, once, in order, and
        // each holding what RFC 3161 section 2.4.2 says it does. millis [0] and
        // micros [1] are IMPLICIT INTEGERs, so they are primitive, and tsa [0] is
        // EXPLICIT and wraps one GeneralName.
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $tail =
            $this->asn1->encodeSequence($this->asn1->encodeInteger(1) . "\x80\x02\x01\xF4\x81\x01\x63")
            . $this->asn1->encodeBoolean(false)
            . $this->asn1->encodeInteger(7)
            . $this->asn1->encodeContext(0, $this->asn1->encodeContext(4, $this->asn1->encodeSequence('')));

        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            $request->imprint,
            $request->hashOid,
            $tail,
            self::NOW,
        ));

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseAcceptsATstInfoExtensionThatIsNotCritical(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            $request->imprint,
            $request->hashOid,
            $request->nonce,
            self::NOW,
            $this->der->extension('1.3.6.1.4.1.99999.3'),
        ));

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseRejectsTokenForOtherBytes(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $other = $client->buildRequest('a different document');

        $response = $this->der->timestampResponse(0, $this->tokenFor($other));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not cover the requested bytes/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsMismatchedNonce(): void
    {
        $client = $this->client(nonce: true);
        $request = $client->buildRequest('payload');

        $tampered = $this->der->timestampToken($this->der->tstInfo(
            $request->imprint,
            $request->hashOid,
            $this->asn1->encodeInteger(999),
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/nonce does not match/');
        $client->parseResponse($this->der->timestampResponse(0, $tampered), $request, self::NOW);
    }

    public function testParseResponseRejectsMissingNonce(): void
    {
        $client = $this->client(nonce: true);
        $request = $client->buildRequest('payload');

        $stripped = $this->der->timestampToken($this->der->tstInfo($request->imprint, $request->hashOid));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/nonce does not match/');
        $client->parseResponse($this->der->timestampResponse(0, $stripped), $request, self::NOW);
    }

    /**
     * TSTInfo sub-structures that are read field by field and then left unbounded.
     *
     * The TSTInfo is signed, so these take the TSA's key, but the token travels
     * verbatim into the /Contents of a published document and a validator that opens
     * it has to be able to decode them.
     *
     * @return array<string, array{string, string, string}>
     */
    public static function unboundedTstInfoProvider(): array
    {
        $asn1 = new Asn1();
        $oid = $asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1');
        $chosen = $asn1->encodeOctetString(\str_repeat('X', 64));

        return [
            // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage } has nothing
            // after the two.
            'chosen bytes after hashedMessage' => [
                $asn1->encodeSequence($oid),
                $chosen,
                'Invalid TSA messageImprint',
            ],
            'hashAlgorithm is not a SEQUENCE' => [
                $asn1->encodeSet($oid),
                '',
                'Invalid TSA messageImprint AlgorithmIdentifier',
            ],
            'hashAlgorithm carries chosen bytes after its OID' => [
                $asn1->encodeSequence($oid . $chosen),
                '',
                'Unsupported TSA messageImprint AlgorithmIdentifier parameters',
            ],
        ];
    }

    #[DataProvider('unboundedTstInfoProvider')]
    public function testParseResponseBoundsTheMessageImprint(
        string $hashAlgorithm,
        string $imprintTail,
        string $message,
    ): void {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $imprint = $this->asn1->encodeSequence(
            $hashAlgorithm . $this->asn1->encodeOctetString($request->imprint) . $imprintTail,
        );
        $tstInfo = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->asn1->encodeObjectIdentifier('1.2.3.4.1')
                . $imprint
                . $this->asn1->encodeInteger(42)
                . $this->der->generalizedTime(1_700_000_000),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $client->parseResponse(
            $this->der->timestampResponse(0, $this->der->signedTimestampToken($tstInfo)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseBoundsTheTstInfoTailAfterTheExtensions(): void
    {
        // RFC 3161 section 2.4.2 puts nothing after extensions [1].
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $tstInfo =
            $this->der->tstInfo(
                $request->imprint,
                $request->hashOid,
                '',
                1_700_000_000,
                $this->der->extension('1.2.3.4.99'),
            ) . '';

        $offset = 0;
        $body = $this->asn1->readTlv($tstInfo, $offset)['value'];
        $trailed = $this->asn1->encodeSequence(
            $body . $this->asn1->encodeContext(7, $this->asn1->encodeOctetString(\str_repeat('X', 64))),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the TSA token extensions/');
        $client->parseResponse(
            $this->der->timestampResponse(0, $this->der->signedTimestampToken($trailed)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseRejectsAnOversizedCertificateBag(): void
    {
        // The bag is unauthenticated, so Cms\Certificate holds it to the same bound
        // Ocsp\Client applies to a response's certs [0]. This is the gate a B-T-only
        // signature passes, Signer applying its own only when validation material is
        // collected.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $bag = \array_fill(0, Certificate::MAX_EMBEDDED_CERTIFICATES + 1, Authority::leaf()->certDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CertificateSet holds more than 32 certificates/');
        $client->parseResponse($this->der->timestampResponse(0, $this->tokenFor($request, $bag)), $request, self::NOW);
    }

    public function testParseResponseRejectsMismatchedDigestAlgorithm(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $wrongAlgorithm = $this->der->timestampToken($this->der->tstInfo($request->imprint, '2.16.840.1.101.3.4.2.3'));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/digest algorithm does not match/');
        $client->parseResponse($this->der->timestampResponse(0, $wrongAlgorithm), $request, self::NOW);
    }

    public function testParseResponseRejectsATokenUnderAnotherPolicy(): void
    {
        // RFC 3161 section 2.4.2: a token answering a request that named a policy has
        // to be issued under it. The fixture issues under 1.2.3.4.1.
        $client = $this->client(policyOid: '1.2.3.4.9');
        $request = $client->buildRequest('payload');
        $this->assertSame('1.2.3.4.9', $request->policyOid);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/policy does not match/');
        $client->parseResponse($this->der->timestampResponse(0, $this->tokenFor($request)), $request, self::NOW);
    }

    public function testParseResponseAcceptsATokenUnderTheRequestedPolicy(): void
    {
        $client = $this->client(policyOid: '1.2.3.4.1');
        $request = $client->buildRequest('payload');
        $token = $this->tokenFor($request);

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseIgnoresThePolicyWhenNoneWasRequested(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $this->assertSame('', $request->policyOid);

        $token = $this->tokenFor($request);
        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseRejectsATokenWhosePolicyIsNotAnOid(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $malformed = $this->der->signedTimestampToken($this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1) . $this->asn1->encodeInteger(7)
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($request->hashOid))
                        . $this->asn1->encodeOctetString($request->imprint),
                ),
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TSA token policy/');
        $client->parseResponse($this->der->timestampResponse(0, $malformed), $request, self::NOW);
    }

    public function testParseResponseRejectsATstInfoVersionThatIsNotAnInteger(): void
    {
        // RFC 3161 section 2.4.2 types version an INTEGER, so the field is decoded
        // rather than stepped over. openssl ts cannot read the result either.
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $malformed = $this->der->signedTimestampToken($this->tstInfoWithHead(
            $this->asn1->encodeOctetString(\str_repeat('M', 64)),
            $this->asn1->encodeInteger(42),
            $request,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TSA token version/');
        $client->parseResponse($this->der->timestampResponse(0, $malformed), $request, self::NOW);
    }

    public function testParseResponseRejectsATstInfoSerialNumberThatIsNotAnInteger(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $malformed = $this->der->signedTimestampToken($this->tstInfoWithHead(
            $this->asn1->encodeInteger(1),
            $this->asn1->encodeOctetString(\str_repeat('M', 64)),
            $request,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TSA token serialNumber/');
        $client->parseResponse($this->der->timestampResponse(0, $malformed), $request, self::NOW);
    }

    /**
     * A TSTInfo answering a request, with the two head fields supplied verbatim.
     */
    private function tstInfoWithHead(string $version, string $serialNumber, Request $request): string
    {
        return $this->asn1->encodeSequence(
            $version
                . $this->asn1->encodeObjectIdentifier('1.2.3.4.1')
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($request->hashOid))
                        . $this->asn1->encodeOctetString($request->imprint),
                )
                . $serialNumber
                . $this->der->generalizedTime(self::NOW),
        );
    }

    #[DataProvider('nonDerTstInfoFieldProvider')]
    public function testParseResponseRejectsANonDerTstInfoField(
        string $policy,
        string $serialNumber,
        string $tail,
    ): void {
        // The policy, the nonce and the serialNumber are held to their own shapes
        // rather than only where a comparison happens to read them, since the default
        // configuration names no policy and the comparison then never runs. openssl ts
        // cannot decode any of these.
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $malformed = $this->der->signedTimestampToken($this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $policy
            . $this->asn1->encodeSequence(
                $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($request->hashOid))
                    . $this->asn1->encodeOctetString($request->imprint),
            )
            . $serialNumber
            . $this->der->generalizedTime(self::NOW)
            . $tail,
        ));

        $this->expectException(Exception::class);
        $client->parseResponse($this->der->timestampResponse(0, $malformed), $request, self::NOW);
    }

    /**
     * @return array<string, array{string, string, string}> [policy, serialNumber, tail]
     */
    public static function nonDerTstInfoFieldProvider(): array
    {
        $policy = "\x06\x04\x2A\x03\x04\x01"; // 1.2.3.4.1
        $serialNumber = "\x02\x01\x2A";

        return [
            // X.690 section 8.19.2: a subidentifier may not begin with 0x80.
            'policy carrying a non-minimal subidentifier' => ["\x06\x02\x80\x01", $serialNumber, ''],
            'policy carrying no subidentifier' => ["\x06\x00", $serialNumber, ''],
            // X.690 section 8.3.2, as the CRL and OCSP serials are held.
            'non-minimal serialNumber' => [$policy, "\x02\x02\x00\x2A", ''],
            'empty serialNumber' => [$policy, "\x02\x00", ''],
            'non-minimal nonce, none requested' => [$policy, $serialNumber, "\x02\x02\x00\x2A"],
            'empty nonce, none requested' => [$policy, $serialNumber, "\x02\x00"],
        ];
    }

    public function testParseResponseRejectsATokenWithAForgedSignature(): void
    {
        // The token structure answers the request, but nothing signed it.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $unsigned = $this->der->timestampToken($this->der->tstInfo($request->imprint, $request->hashOid), [
            Authority::ocsp()->certDer,
        ]);

        $this->expectException(Exception::class);
        $client->parseResponse($this->der->timestampResponse(0, $unsigned), $request, self::NOW);
    }

    public function testParseResponseRejectsATokenSignedByAnotherKey(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        // Signed by the ltv CA but naming the ocsp CA as the signer.
        $token = $this->der->signedTimestampToken($this->der->tstInfo($request->imprint, $request->hashOid));
        $forged = $this->der->signedTimestampToken(
            $this->der->tstInfo($request->imprint, $request->hashOid),
            [],
            Authority::ltv(),
        );
        $this->assertNotSame($token, $forged);

        $swapped = \str_replace(Authority::ltv()->certDer, Authority::ocsp()->certDer, $forged);

        $this->expectException(Exception::class);
        $client->parseResponse($this->der->timestampResponse(0, $swapped), $request, self::NOW);
    }

    public function testParseResponseRejectsArbitraryToken(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        // A well-formed SEQUENCE that is not a timestamp token at all.
        $bogus = $this->asn1->encodeSequence($this->asn1->encodeOctetString('attacker chosen'));

        $this->expectException(Exception::class);
        $client->parseResponse($this->der->timestampResponse(0, $bogus), $request, self::NOW);
    }

    public function testParseResponseRejectsNonTstInfoContent(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        // A complete encapContentInfo carrying its content under id-data rather than
        // id-ct-TSTInfo, so it is the content type that is refused here.
        $signedData = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(3)
                . $this->asn1->encodeSet('')
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1')
                        . $this->asn1->encodeContext(0, $this->asn1->encodeOctetString('attacker chosen')),
                )
                . $this->asn1->encodeSet(''),
        );
        $token = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(Der::OID_SIGNED_DATA) . $this->asn1->encodeContext(0, $signedData),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not carry a TSTInfo/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseRejectsEmpty(): void
    {
        $client = $this->client();
        $this->expectException(Exception::class);
        $client->parseResponse('', $client->buildRequest('x'), self::NOW);
    }

    public function testParseResponseRejectsNonSequenceRoot(): void
    {
        $client = $this->client();
        $this->expectException(Exception::class);
        $client->parseResponse($this->asn1->encodeInteger(0), $client->buildRequest('x'), self::NOW);
    }

    public function testParseResponseRejectsInvalidStatusStructure(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('x');
        $bad = $this->asn1->encodeSequence($this->asn1->encodeInteger(0) . $this->tokenFor($request));

        $this->expectException(Exception::class);
        $client->parseResponse($bad, $request, self::NOW);
    }

    public function testParseResponseRejectsNonIntegerStatus(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('x');
        $bad = $this->asn1->encodeSequence(
            $this->asn1->encodeSequence($this->asn1->encodeOctetString('x')) . $this->tokenFor($request),
        );

        $this->expectException(Exception::class);
        $client->parseResponse($bad, $request, self::NOW);
    }

    public function testParseResponseRejectsRejectedStatus(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('x');

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/rejected/');
        $client->parseResponse($this->der->timestampResponse(2, $this->tokenFor($request)), $request, self::NOW);
    }

    public function testParseResponseRejectsMissingToken(): void
    {
        $client = $this->client();
        $noToken = $this->asn1->encodeSequence($this->asn1->encodeSequence($this->asn1->encodeInteger(0)));

        $this->expectException(Exception::class);
        $client->parseResponse($noToken, $client->buildRequest('x'), self::NOW);
    }

    public function testParseResponseRejectsNonSequenceToken(): void
    {
        $client = $this->client();
        $bad = $this->asn1->encodeSequence(
            $this->asn1->encodeSequence($this->asn1->encodeInteger(0)) . $this->asn1->encodeInteger(5),
        );

        $this->expectException(Exception::class);
        $client->parseResponse($bad, $client->buildRequest('x'), self::NOW);
    }

    public function testRequestTokenUsesTransport(): void
    {
        $client = $this->client(nonce: true);

        $captured = '';
        $transport = function (string $request) use (&$captured, $client): string {
            $captured = $request;
            // Answer the request that was actually sent, as a TSA would.
            $parsed = $this->requestFromDer($request);

            return $this->der->timestampResponse(0, $this->tokenFor($parsed));
        };

        $token = $client->requestToken('payload', $transport, self::NOW);
        $this->assertNotSame('', $token);

        $offset = 0;
        $root = $this->asn1->readTlv($captured, $offset);
        $this->assertSame(0x30, $root['tag']);
    }

    public function testRequestTokenRejectsUnrelatedToken(): void
    {
        $client = $this->client(nonce: true);
        $other = $this->client()->buildRequest('something else');
        $response = $this->der->timestampResponse(0, $this->tokenFor($other));

        $this->expectException(Exception::class);
        $client->requestToken('payload', static fn(string $_request): string => $response, self::NOW);
    }

    public function testRequestTokenRejectsNonStringTransportResult(): void
    {
        $transport = static fn(string $request): int => \strlen($request);
        $this->expectException(Exception::class);
        $this->client()->requestToken('payload', $transport);
    }

    public function testTokenCertificatesReturnsEmbeddedCertificates(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $token = $this->tokenFor($request, [Authority::responder()->certDer]);

        // A signed token always carries the TSA's own certificate first, since the
        // signature cannot be checked without it.
        $this->assertSame(
            [Authority::tsa()->certDer, Authority::responder()->certDer],
            $client->tokenCertificates($token),
        );
    }

    public function testTokenCertificatesDropsAnEntryThatIsNotACertificate(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        // The certificates field is outside signedAttrs and covered by no signature,
        // so a member that is not a certificate is dropped by the lenient reading.
        $junk = $this->asn1->encodeSequence($this->asn1->encodeInteger(7));
        $token = $this->tokenFor($request, [$junk]);

        $this->assertSame([Authority::tsa()->certDer], $client->tokenCertificates($token));
    }

    public function testParseResponseRejectsATokenWhoseCertificateSetHoldsANonCertificate(): void
    {
        // parseResponse() decides whether to hand the token back for Builder to embed
        // verbatim, so it holds the bag to the strict reading: dropping a member would
        // leave its bytes in the embedded token either way.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $junk = $this->asn1->encodeSequence($this->asn1->encodeInteger(7));
        $token = $this->tokenFor($request, [$junk]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CertificateSet holds a member that is not a certificate/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseRejectsATokenWhoseCertificateSetHoldsATaggedMember(): void
    {
        // RFC 5652 section 10.2.2 types the field as a set of CertificateChoices, so
        // a tagged alternative is refused by the strict reading along with a SEQUENCE
        // that is not a certificate.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tagged = $this->asn1->encodeContext(3, \str_repeat('X', 64));
        $token = $this->tokenFor($request, [$tagged]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/CertificateSet holds a member that is not a certificate/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    /**
     * A genTime the token cannot have been issued at, and one that is not a time.
     *
     * @return array<string, array{int|string}>
     */
    public static function badGenTimeProvider(): array
    {
        return [
            'years in the past' => [1_000_000_000],
            'years in the future' => [4_000_000_000],
            'the epoch' => [0],
            'just outside the skew' => [self::NOW + Client::CLOCK_SKEW + 60],
            'not a time at all' => ['octet string'],
        ];
    }

    #[DataProvider('badGenTimeProvider')]
    public function testParseResponseRejectsAGenTimeThatIsNotNearTheRequest(int|string $genTime): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $tstInfo = \is_int($genTime)
            ? $this->der->tstInfo($request->imprint, $request->hashOid, '', $genTime)
            : $this->tstInfoWithGenTime($request, $this->asn1->encodeOctetString($genTime));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/genTime/');
        $client->parseResponse(
            $this->der->timestampResponse(0, $this->der->signedTimestampToken($tstInfo)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseAcceptsAGenTimeInsideTheSkew(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid, '', self::NOW - 60);
        $token = $this->der->signedTimestampToken($tstInfo);

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    /**
     * Certificates that are not a TSA's, with the purpose each one does carry.
     *
     * @return array<string, array{Authority, string}>
     */
    public static function nonTsaCertificateProvider(): array
    {
        return [
            'a CA, with no extended key usage' => [Authority::ocsp(), 'no extended key usage'],
            'a signing leaf, with no extended key usage' => [Authority::leaf(), 'no extended key usage'],
            'an OCSP responder, reserved for OCSP' => [Authority::responder(), '1.3.6.1.5.5.7.3.9'],
        ];
    }

    #[DataProvider('nonTsaCertificateProvider')]
    public function testParseResponseRejectsATokenSignedWithoutTheTimestampingPurpose(
        Authority $signer,
        string $purpose,
    ): void {
        // RFC 3161 section 2.3: the TSA signs with a key reserved for timestamping,
        // marked by id-kp-timeStamping as the sole purpose.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid);
        $token = $this->der->signedTimestampToken($tstInfo, [], $signer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not reserved for timestamping: ' . \preg_quote($purpose, '/') . '$/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseRejectsATsaCertificateWithANonCriticalKeyUsage(): void
    {
        // RFC 3161 section 2.3 requires the extended key usage extension to be
        // critical as well as present.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid);
        $token = $this->der->signedTimestampToken($tstInfo, [], Authority::laxTsa());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/extended key usage is not critical/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseRejectsATsaCertificateWhoseKeyUsageForbidsSigning(): void
    {
        // RFC 5280 section 4.2.1.3 reserves digitalSignature for a signature that is
        // not over a certificate or a CRL, which is what a token carries. The purpose
        // says what the key is for, the key usage whether it may sign at all.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid);
        $token = $this->der->signedTimestampToken($tstInfo, [], Authority::unsigningTsa());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/key usage does not admit signing/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseRejectsATsaCertificateExpiredAtGenTime(): void
    {
        // The certificate has to cover the instant the token attests, the signature
        // verifying just as well under a key retired years before.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid);
        $token = $this->der->signedTimestampToken($tstInfo, [], Authority::expiredTsa());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/did not cover the token genTime/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseRejectsATokenWithoutTheSigningCertificateAttribute(): void
    {
        // RFC 3161 section 2.4.2 requires the ESS signing-certificate attribute of a
        // token. It is the only signed field naming the certificate the checks above
        // run against, sid and the certificate bag being covered by no signature.
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid, $request->nonce);
        $token = $this->der->signedTimestampToken($tstInfo, essCertDer: '');

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries no signing-certificate attribute/');
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseAcceptsATokenWithoutTheAttributeWhenTheVerifierIsInjected(): void
    {
        // A host whose TSA emits no such attribute injects a verifier constructed
        // without $requireSigningCertificate.
        $client = new Client(
            new Config('https://tsa.example.org/tsa'),
            $this->asn1,
            null,
            new SignedDataVerifier($this->asn1),
        );
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid, $request->nonce);
        $token = $this->der->signedTimestampToken($tstInfo, essCertDer: '');

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseAcceptsAGenTimeAtTheEdgeOfTheDefaultSkew(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid, '', self::NOW + Client::CLOCK_SKEW);
        $token = $this->der->signedTimestampToken($tstInfo);

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseAcceptsAWidenedClockSkew(): void
    {
        // The genTime bound is the one comparison this library makes against the
        // local clock, and the skew is configurable.
        $ahead = Client::CLOCK_SKEW + 60;
        $client = new Client(new Config(host: 'https://tsa.example.org', nonceEnabled: false), clockSkew: $ahead);
        $request = $client->buildRequest('payload');
        $tstInfo = $this->der->tstInfo($request->imprint, $request->hashOid, '', self::NOW + $ahead);
        $token = $this->der->signedTimestampToken($tstInfo);

        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testConstructorRejectsANegativeClockSkew(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TSA clock skew/');
        new Client(new Config(host: 'https://tsa.example.org'), clockSkew: -1);
    }

    public function testParseResponseRejectsATokenWithTrailingBytes(): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $response = $this->der->timestampResponse(0, $this->tokenFor($request));

        $offset = 0;
        $root = $this->asn1->readTlv($response, $offset);
        $trailed = $this->asn1->encodeSequence($root['value'] . $this->asn1->encodeInteger(1));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes/');
        $client->parseResponse($trailed, $request, self::NOW);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function fractionalGenTimeProvider(): array
    {
        return [
            'one digit' => ['20231114221320.5Z'],
            'three digits' => ['20231114221320.123Z'],
        ];
    }

    /**
     * RFC 3161 section 2.4.2: "The ASN.1 GeneralizedTime syntax can include
     * fraction-of-second details. Such syntax, without the restrictions from
     * [RFC2459] Sect. 4.1.2.5.2 ... may be used here." An OpenSSL-backed TSA emits
     * one whenever its clock_precision_digits is set.
     */
    #[DataProvider('fractionalGenTimeProvider')]
    public function testParseResponseAcceptsAFractionalGenTime(string $genTime): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');

        $tstInfo = $this->tstInfoWithGenTime(
            $request,
            "\x18" . $this->asn1->encodeLength(\strlen($genTime)) . $genTime,
        );

        $client->parseResponse(
            $this->der->timestampResponse(0, $this->der->signedTimestampToken($tstInfo)),
            $request,
            self::NOW,
        );
        $this->expectNotToPerformAssertions();
    }

    /**
     * Rebuild a TSTInfo with an arbitrary element in place of genTime.
     */
    private function tstInfoWithGenTime(Request $request, string $genTime): string
    {
        return $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->asn1->encodeObjectIdentifier('1.2.3.4.1')
            . $this->asn1->encodeSequence(
                $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($request->hashOid))
                    . $this->asn1->encodeOctetString($request->imprint),
            )
            . $this->asn1->encodeInteger(42)
            . $genTime,
        );
    }

    public function testTokenCertificatesReturnsEmptyWhenAbsent(): void
    {
        $client = $this->client();
        $token = $this->der->timestampToken($this->der->tstInfo('x', '2.16.840.1.101.3.4.2.1'));

        $this->assertSame([], $client->tokenCertificates($token));
    }

    /**
     * Tokens that are structurally wrong before the imprint can be compared.
     *
     * @return array<string, array{callable(Asn1, Der): string}>
     */
    public static function malformedTokenProvider(): array
    {
        return [
            'content not tagged' => [
                static fn(Asn1 $asn1, Der $_der): string => $asn1->encodeSequence(
                    $asn1->encodeObjectIdentifier(Der::OID_SIGNED_DATA) . $asn1->encodeSequence(''),
                ),
            ],
            'signed data not a sequence' => [
                static fn(Asn1 $asn1, Der $_der): string => $asn1->encodeSequence(
                    $asn1->encodeObjectIdentifier(Der::OID_SIGNED_DATA)
                        . $asn1->encodeContext(0, $asn1->encodeInteger(1)),
                ),
            ],
            'encap content not a sequence' => [
                static fn(Asn1 $asn1, Der $_der): string => self::signedData(
                    $asn1,
                    $asn1->encodeInteger(3) . $asn1->encodeSet('') . $asn1->encodeInteger(9),
                ),
            ],
            'econtent absent' => [
                static fn(Asn1 $asn1, Der $_der): string => self::signedData(
                    $asn1,
                    $asn1->encodeInteger(3) . $asn1->encodeSet('')
                        . $asn1->encodeSequence($asn1->encodeObjectIdentifier(Der::OID_TST_INFO)),
                ),
            ],
            'econtent not tagged' => [
                static fn(Asn1 $asn1, Der $_der): string => self::signedData(
                    $asn1,
                    $asn1->encodeInteger(3) . $asn1->encodeSet('')
                        . $asn1->encodeSequence(
                            $asn1->encodeObjectIdentifier(Der::OID_TST_INFO) . $asn1->encodeInteger(1),
                        ),
                ),
            ],
            'econtent not an octet string' => [
                static fn(Asn1 $asn1, Der $_der): string => self::signedData(
                    $asn1,
                    $asn1->encodeInteger(3) . $asn1->encodeSet('')
                        . $asn1->encodeSequence(
                            $asn1->encodeObjectIdentifier(Der::OID_TST_INFO)
                                . $asn1->encodeContext(0, $asn1->encodeInteger(1)),
                        ),
                ),
            ],
            'tstinfo not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => $der->timestampToken($asn1->encodeInteger(1)),
            ],
            'message imprint not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => $der->timestampToken($asn1->encodeSequence(
                    $asn1->encodeInteger(1) . $asn1->encodeObjectIdentifier('1.2.3.4.1') . $asn1->encodeInteger(7),
                )),
            ],
            'hashed message not an octet string' => [
                static fn(Asn1 $asn1, Der $der): string => $der->timestampToken($asn1->encodeSequence(
                    $asn1->encodeInteger(1) . $asn1->encodeObjectIdentifier('1.2.3.4.1')
                        . $asn1->encodeSequence(
                            $asn1->encodeSequence($asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1'))
                                . $asn1->encodeInteger(5),
                        ),
                )),
            ],
        ];
    }

    /**
     * Wrap SignedData content octets as a token ContentInfo.
     */
    private static function signedData(Asn1 $asn1, string $content): string
    {
        return $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier(Der::OID_SIGNED_DATA)
                . $asn1->encodeContext(0, $asn1->encodeSequence($content)),
        );
    }

    /**
     * @param callable(Asn1, Der): string $build
     */
    #[DataProvider('malformedTokenProvider')]
    public function testParseResponseRejectsMalformedTokens(callable $build): void
    {
        $client = $this->client();
        $request = $client->buildRequest('payload');
        $token = $build($this->asn1, $this->der);

        $this->expectException(Exception::class);
        $client->parseResponse($this->der->timestampResponse(0, $token), $request, self::NOW);
    }

    public function testParseResponseSkipsTheOptionalFieldsBeforeTheNonce(): void
    {
        // accuracy (SEQUENCE) and ordering (BOOLEAN) may sit between genTime and
        // the nonce, and tsa [0] sits after it.
        $client = $this->client(nonce: true);
        $request = $client->buildRequest('payload');

        $tstInfo = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->asn1->encodeObjectIdentifier('1.2.3.4.1')
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($request->hashOid))
                        . $this->asn1->encodeOctetString($request->imprint),
                )
                . $this->asn1->encodeInteger(42)
                . $this->der->generalizedTime(1_700_000_000)
                . $this->asn1->encodeSequence($this->asn1->encodeInteger(1))
                . $this->asn1->encodeBoolean(false)
                . $request->nonce
                . $this->asn1->encodeContext(0, $this->asn1->encodeSequence('')),
        );

        $token = $this->der->signedTimestampToken($tstInfo);
        $this->assertSame($token, $client->parseResponse(
            $this->der->timestampResponse(0, $token),
            $request,
            self::NOW,
        ));
    }

    public function testParseResponseStopsLookingForTheNonceAtATaggedField(): void
    {
        // tsa [0] follows the nonce, so a token that reaches it without one has
        // no nonce to match.
        $client = $this->client(nonce: true);
        $request = $client->buildRequest('payload');

        $tstInfo = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
                . $this->asn1->encodeObjectIdentifier('1.2.3.4.1')
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($request->hashOid))
                        . $this->asn1->encodeOctetString($request->imprint),
                )
                . $this->asn1->encodeInteger(42)
                . $this->der->generalizedTime(1_700_000_000)
                . $this->asn1->encodeContext(0, $this->asn1->encodeSequence('')),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/nonce does not match/');
        $client->parseResponse(
            $this->der->timestampResponse(0, $this->der->timestampToken($tstInfo)),
            $request,
            self::NOW,
        );
    }

    /**
     * Recover the imprint and nonce a DER TimeStampReq carries.
     */
    private function requestFromDer(string $der): Request
    {
        $offset = 0;
        $root = $this->asn1->readTlv($der, $offset);

        $inner = 0;
        $this->asn1->readTlv($root['value'], $inner); // version
        $imprint = $this->asn1->readTlv($root['value'], $inner);

        $miOffset = 0;
        $algId = $this->asn1->readTlv($imprint['value'], $miOffset);
        $hashed = $this->asn1->readTlv($imprint['value'], $miOffset);

        $algOffset = 0;
        $oid = $this->asn1->readTlv($algId['value'], $algOffset);

        $nonce = '';
        while ($inner < \strlen($root['value'])) {
            $field = $this->asn1->readTlv($root['value'], $inner);
            if ($field['tag'] === 0x02) {
                $nonce = $field['raw'];
            }
        }

        return new Request($der, $hashed['value'], $this->asn1->decodeObjectIdentifier($oid['value']), $nonce);
    }
}
