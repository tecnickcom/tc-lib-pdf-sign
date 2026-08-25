<?php

declare(strict_types=1);

/**
 * ValidationMaterialTest.php
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

namespace Test\Ltv;

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Ltv\SkipReason;
use Com\Tecnick\Pdf\Sign\Ltv\ValidationMaterial;
use Com\Tecnick\Pdf\Sign\Ocsp\Client as OcspClient;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Der;

/**
 * ValidationMaterial Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(ValidationMaterial::class)]
#[CoversClass(SkipReason::class)]
final class ValidationMaterialTest extends TestCase
{
    /**
     * A moment inside the validity interval the fixture responses declare.
     */
    private const NOW = 1_800_000_000;

    private ValidationMaterial $material;

    private OcspClient $ocsp;

    private Asn1 $asn1;

    private Der $der;

    private string $ltvPem = '';

    private string $caPem = '';

    private string $leafDer = '';

    private string $caDer = '';

    protected function setUp(): void
    {
        $this->ocsp = new OcspClient();
        $this->material = new ValidationMaterial($this->ocsp);
        $this->asn1 = new Asn1();
        $this->der = new Der($this->asn1);
        $this->ltvPem = (string) \file_get_contents(__DIR__ . '/../data/ltv_cert.pem');
        $this->caPem = (string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem');
        $leafPem = (string) \file_get_contents(__DIR__ . '/../data/ocsp_leaf.pem');
        $this->leafDer = $this->pemToDer($leafPem);
        $this->caDer = $this->pemToDer($this->caPem);
    }

    private function pemToDer(string $pem): string
    {
        return Certificate::pemToDer($pem);
    }

    /**
     * A validated OCSP response for the leaf certificate.
     */
    private function goodResponse(): string
    {
        return $this->der->ocspResponse($this->ocsp->build($this->caDer, $this->leafDer)->certId);
    }

    public function testCertificateOcspUrlsExtractsOnlyOcsp(): void
    {
        $urls = $this->material->certificateOcspUrls($this->ltvPem);
        $this->assertSame(['http://ocsp.example.org/r'], $urls);
    }

    public function testCertificateCrlUrlsExtractsAll(): void
    {
        $urls = $this->material->certificateCrlUrls($this->ltvPem);
        $this->assertSame(['http://crl.example.org/root.crl', 'http://crl2.example.org/root.crl'], $urls);
    }

    public function testCertificateUrlsIgnoreTextEmbeddedInNeighbouringFields(): void
    {
        // The fixture carries no id-ad-ocsp access description and no URI
        // GeneralName in its distribution point, only a caIssuers URI and a
        // directoryName holding text of the shape a responder URL has. RFC 5280
        // sections 4.2.2.1 and 4.2.1.13 put a location in neither field, so a reader
        // that decodes the DER answers with nothing.
        $pem = (string) \file_get_contents(__DIR__ . '/../data/ocsp_url_injection.pem');

        $this->assertSame([], $this->material->certificateOcspUrls($pem));
        $this->assertSame([], $this->material->certificateCrlUrls($pem));
    }

    public function testCertificateOcspUrlsBoundsTheListAndReportsTheExcess(): void
    {
        // Every URL becomes a call to the host's transport, so the list is bounded
        // and the excess is reported rather than dropped.
        $descriptions = '';
        $count = ValidationMaterial::MAX_URLS + 4;
        for ($idx = 0; $idx < $count; ++$idx) {
            $url = 'http://ocsp' . $idx . '.example.org';
            $descriptions .= $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1')
                . "\x86"
                . $this->asn1->encodeLength(\strlen($url))
                . $url,
            );
        }

        $pem = $this->certificateWithExtensions(['1.3.6.1.5.5.7.1.1' => $this->asn1->encodeSequence($descriptions)]);

        $skipped = [];
        $urls = $this->material->certificateOcspUrls($pem, static function (
            string $source,
            string $url,
            string $_reason,
            SkipReason $code,
        ) use (&$skipped): void {
            $skipped[] = [$source, $url, $code];
        });

        $this->assertCount(ValidationMaterial::MAX_URLS, $urls);
        $this->assertSame('http://ocsp0.example.org', \reset($urls));
        $this->assertCount(4, $skipped);
        $this->assertSame(
            ['ocsp', 'http://ocsp' . ValidationMaterial::MAX_URLS . '.example.org', SkipReason::NotAttempted],
            \reset($skipped),
        );
    }

    /**
     * A parseable certificate carrying the given extensions and nothing else.
     *
     * The URL readers decode the certificate's own DER, so the shapes they have to
     * walk past are stated here as DER rather than as fixtures on disk.
     *
     * @param array<string, string> $extensions Extension OID to extnValue octets.
     */
    private function certificateWithExtensions(array $extensions): string
    {
        $encoded = '';
        foreach ($extensions as $oid => $value) {
            $encoded .= $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier($oid) . $this->asn1->encodeOctetString($value),
            );
        }

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeContext(0, $this->asn1->encodeInteger(2))
                . $this->asn1->encodeInteger(7)
                . $this->asn1->encodeSequence('')
                . $this->asn1->encodeSequence('')
                . $this->asn1->encodeSequence("\x18\x0F20200101000000Z\x18\x0F20400101000000Z")
                . $this->asn1->encodeSequence('')
                . $this->asn1->encodeSequence($this->asn1->encodeSequence('') . "\x03\x02\x00\x01")
                . $this->asn1->encodeContext(3, $this->asn1->encodeSequence($encoded)),
        );

        return Certificate::derToPem($this->asn1->encodeSequence(
            $tbs . $this->asn1->encodeSequence('') . "\x03\x02\x00\x01",
        ));
    }

    /**
     * AIA shapes that name no OCSP responder.
     *
     * @return array<string, array{string}>
     */
    public static function unusableAiaProvider(): array
    {
        $asn1 = new Asn1();
        $uri = "\x86" . $asn1->encodeLength(19) . 'http://evil.example';

        return [
            // accessMethod is caIssuers, not id-ad-ocsp.
            'another access method' => [$asn1->encodeSequence($asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.2') . $uri,
            ))],
            // id-ad-ocsp, but the location is a directoryName rather than a URI.
            'a location that is not a uri' => [$asn1->encodeSequence($asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1') . $asn1->encodeContext(4, ''),
            ))],
            // accessMethod is not an OBJECT IDENTIFIER.
            'an access method that is not an oid' => [$asn1->encodeSequence($asn1->encodeSequence(
                $asn1->encodeInteger(1) . $uri,
            ))],
            // The description ends after the accessMethod, so readTlv throws.
            'a truncated access description' =>
                [$asn1->encodeSequence($asn1->encodeSequence($asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1')))],
            'an extension that is not a sequence' => [$asn1->encodeInteger(1)],
        ];
    }

    #[DataProvider('unusableAiaProvider')]
    public function testCertificateOcspUrlsIgnoresAnAiaThatNamesNoResponder(string $extension): void
    {
        $pem = $this->certificateWithExtensions(['1.3.6.1.5.5.7.1.1' => $extension]);
        $this->assertSame([], $this->material->certificateOcspUrls($pem));
    }

    /**
     * CRL distribution point shapes that name no list to fetch.
     *
     * @return array<string, array{string}>
     */
    public static function unusableCrlDistributionPointProvider(): array
    {
        $asn1 = new Asn1();
        $uri = "\x86" . $asn1->encodeLength(19) . 'http://evil.example';

        return [
            'an empty distribution point' => [$asn1->encodeSequence($asn1->encodeSequence(''))],
            // reasons [1] first: the point names no distributionPoint at all.
            'no distribution point name' => [$asn1->encodeSequence($asn1->encodeSequence("\x81\x02\x05\xA0"))],
            // nameRelativeToCRLIssuer [1] rather than fullName [0].
            'a relative name' => [$asn1->encodeSequence($asn1->encodeSequence($asn1->encodeContext(0, "\xA1\x00")))],
            // fullName holding a directoryName rather than a URI.
            'a full name that is not a uri' =>
                [$asn1->encodeSequence($asn1->encodeSequence($asn1->encodeContext(0, $asn1->encodeContext(0, $asn1->encodeContext(
                    4,
                    '',
                )))))],
            // The distributionPoint [0] ends before its CHOICE, so readTlv throws.
            'a truncated distribution point name' => [$asn1->encodeSequence($asn1->encodeSequence($asn1->encodeContext(
                0,
                '',
            )))],
            'an extension that is not a sequence' => [$uri],
        ];
    }

    #[DataProvider('unusableCrlDistributionPointProvider')]
    public function testCertificateCrlUrlsIgnoresAPointThatNamesNoList(string $extension): void
    {
        $pem = $this->certificateWithExtensions(['2.5.29.31' => $extension]);
        $this->assertSame([], $this->material->certificateCrlUrls($pem));
    }

    public function testCertificateUrlsRejectAUriCarryingAControlCharacter(): void
    {
        // A GeneralName is an IA5String, which admits control characters, so the URL
        // is held to the pattern Timestamp\Config holds the TSA URL to.
        $asn1 = $this->asn1;
        $url = "http://good.example/a\x01b";
        $uri = "\x86" . $asn1->encodeLength(\strlen($url)) . $url;

        $pem = $this->certificateWithExtensions([
            '1.3.6.1.5.5.7.1.1' => $asn1->encodeSequence($asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1') . $uri,
            )),
            '2.5.29.31' => $asn1->encodeSequence($asn1->encodeSequence($asn1->encodeContext(0, $asn1->encodeContext(
                0,
                $uri,
            )))),
        ]);

        $this->assertSame([], $this->material->certificateOcspUrls($pem));
        $this->assertSame([], $this->material->certificateCrlUrls($pem));
    }

    public function testCertificateUrlsReportAUrlTheTransportCannotBeGiven(): void
    {
        // A URL the pattern refuses is reported like one past MAX_URLS. An ldap://
        // distribution point is what an enterprise authority commonly names.
        $asn1 = $this->asn1;
        $ldap = 'ldap://directory.example.org/cn=CA?certificateRevocationList';
        $control = "http://good.example/a\x01b";

        $pem = $this->certificateWithExtensions([
            '1.3.6.1.5.5.7.1.1' => $asn1->encodeSequence($asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1')
                . "\x86"
                . $asn1->encodeLength(\strlen($control))
                . $control,
            )),
            '2.5.29.31' => $asn1->encodeSequence($asn1->encodeSequence($asn1->encodeContext(0, $asn1->encodeContext(
                0,
                "\x86" . $asn1->encodeLength(\strlen($ldap)) . $ldap,
            )))),
        ]);

        $skipped = [];
        $observer = static function (string $source, string $url, string $_reason, SkipReason $code) use (
            &$skipped,
        ): void {
            $skipped[] = [$source, $url, $code];
        };

        $this->assertSame([], $this->material->certificateOcspUrls($pem, $observer));
        $this->assertSame([], $this->material->certificateCrlUrls($pem, $observer));

        $this->assertSame(
            [
                ['ocsp', $control, SkipReason::NotAttempted],
                ['crl',  $ldap,    SkipReason::NotAttempted],
            ],
            $skipped,
        );
    }

    public function testCertificateCrlUrlsReadsEveryUriOfAFullName(): void
    {
        // GeneralNames is a SEQUENCE OF, so one distribution point may name several
        // mirrors, and a non-URI member among them is passed over rather than ending
        // the walk.
        $asn1 = $this->asn1;
        $first = "\x86" . $asn1->encodeLength(20) . 'http://one.example/c';
        $second = "\x86" . $asn1->encodeLength(20) . 'http://two.example/c';

        $pem = $this->certificateWithExtensions([
            '2.5.29.31' => $asn1->encodeSequence($asn1->encodeSequence($asn1->encodeContext(0, $asn1->encodeContext(
                0,
                $first . $asn1->encodeContext(4, '') . $second,
            )))),
        ]);

        $this->assertSame(['http://one.example/c', 'http://two.example/c'], $this->material->certificateCrlUrls($pem));
    }

    public function testUrlsEmptyWhenExtensionAbsent(): void
    {
        // The OCSP CA fixture carries no AIA or CRL distribution point extensions.
        $this->assertSame([], $this->material->certificateOcspUrls($this->caPem));
        $this->assertSame([], $this->material->certificateCrlUrls($this->caPem));
    }

    public function testCertificateUrlsEmptyForUnparseableCertificate(): void
    {
        // Collection is best-effort: a certificate that cannot be parsed yields no
        // URLs rather than aborting the operation. Its DER is obtained separately, so
        // the certificate is still embeddable.
        \set_error_handler(static fn(): bool => true);
        try {
            $this->assertSame([], $this->material->certificateOcspUrls('not-a-certificate'));
            $this->assertSame([], $this->material->certificateCrlUrls('not-a-certificate'));
        } finally {
            \restore_error_handler();
        }
    }

    public function testCertificatesDeduplicates(): void
    {
        $leafPem = (string) \file_get_contents(__DIR__ . '/../data/ocsp_leaf.pem');
        $ders = $this->material->certificates([$leafPem, $leafPem, $this->caPem]);
        $this->assertCount(2, $ders);
        $this->assertSame([$this->leafDer, $this->caDer], $ders);
    }

    public function testCertificatesRejectsInvalidPem(): void
    {
        $this->expectException(Exception::class);
        $this->material->certificates(["-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----"]);
    }

    public function testCertificatesRejectsAnEntryThatIsNotACertificate(): void
    {
        // Each entry is parsed as a certificate, not merely decoded.
        $this->expectException(Exception::class);
        $this->material->certificates([\base64_encode('hello world')]);
    }

    public function testCertificatesRejectsABundleOfCertificates(): void
    {
        $leafPem = (string) \file_get_contents(__DIR__ . '/../data/ocsp_leaf.pem');

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/more than one certificate/');
        $this->material->certificates([$leafPem . $this->caPem]);
    }

    public function testCertificatesRejectsAnEntryThatIsNotAString(): void
    {
        // Typed loosely on purpose: an entry that is not a string would reach
        // pemToDer() as a TypeError rather than an Exception.
        /** @var list<string> $certs */
        $certs = [$this->caPem, 42];

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid certificate 1/');
        $this->material->certificates($certs);
    }

    public function testAUrlThatIsNotAStringIsRefused(): void
    {
        // The same rule for the three entry points that take a URL list. On the
        // fetch routes the catch that turns a failure into a skip would swallow the
        // closure's own TypeError, and skip() would then raise a second one.
        /** @var list<string> $urls */
        $urls = [7];
        $material = $this->material;
        $caDer = $this->caDer;
        $leafDer = $this->leafDer;

        $calls = [
            'ocsp' => static fn(): array => $material->fetchOcsp($caDer, $leafDer, $urls, static fn(): string => ''),
            'crl' => static fn(): array => $material->fetchCrl($urls, static fn(): string => '', $caDer, $leafDer),
        ];

        foreach ($calls as $source => $call) {
            try {
                $call();
                $this->fail('Expected an Exception for ' . $source);
            } catch (Exception $e) {
                $this->assertSame('Invalid ' . $source . ' URL 0', $e->getMessage());
            }
        }

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid crl URL 0/');
        $this->material->reportNotAttempted('crl', $urls, 'not attempted', null);
    }

    public function testFetchOcspBuildsRequestAndDeduplicates(): void
    {
        $response = $this->goodResponse();

        $captured = [];
        $transport = static function (string $url, string $request) use (&$captured, $response): string {
            $captured[] = ['url' => $url, 'request' => $request];
            return $response;
        };

        $responses = $this->material->fetchOcsp(
            $this->caDer,
            $this->leafDer,
            ['http://ocsp.a.example', 'http://ocsp.b.example'],
            $transport,
            self::NOW,
        );

        // Two URLs, identical responses collapse to one.
        $this->assertSame([$response], $responses);
        $this->assertCount(2, $captured);
        // The transport received a DER OCSP request (SEQUENCE).
        $firstCapture = $captured[0] ?? null;
        if (!\is_array($firstCapture)) {
            $this->fail('Expected a captured OCSP request');
        }

        $this->assertSame("\x30", $firstCapture['request'][0]);
    }

    public function testFetchOcspSkipsFailingUrl(): void
    {
        $response = $this->goodResponse();
        $transport = static function (string $url) use ($response): string {
            if (\str_contains($url, 'bad')) {
                throw new \RuntimeException('boom');
            }

            return $response;
        };

        $responses = $this->material->fetchOcsp(
            $this->caDer,
            $this->leafDer,
            ['http://bad.example', 'http://good.example'],
            $transport,
            self::NOW,
        );

        $this->assertSame([$response], $responses);
    }

    public function testFetchOcspSkipsResponderErrors(): void
    {
        // An OCSPResponse carrying only a status is refused rather than collected.
        $error = $this->der->ocspResponseBytes(3, null);

        $responses = $this->material->fetchOcsp(
            $this->caDer,
            $this->leafDer,
            ['http://ocsp.example'],
            static fn(string $_url, string $_request): string => $error,
            self::NOW,
        );

        $this->assertSame([], $responses);
    }

    public function testFetchOcspSkipsResponseAboutAnotherCertificate(): void
    {
        $unrelated = $this->der->ocspResponse($this->ocsp->build($this->caDer, $this->caDer)->certId);

        $responses = $this->material->fetchOcsp(
            $this->caDer,
            $this->leafDer,
            ['http://ocsp.example'],
            static fn(string $_url, string $_request): string => $unrelated,
            self::NOW,
        );

        $this->assertSame([], $responses);
    }

    public function testFetchOcspSkipsRevokedResponse(): void
    {
        $certId = $this->ocsp->build($this->caDer, $this->leafDer)->certId;
        $revoked = $this->der->ocspResponse(
            $certId,
            "\xA1" . (new \Com\Tecnick\Pdf\Sign\Cms\Asn1())->encodeLength(17)
                . $this->der->generalizedTime(1_700_000_000),
        );

        $responses = $this->material->fetchOcsp(
            $this->caDer,
            $this->leafDer,
            ['http://ocsp.example'],
            static fn(string $_url, string $_request): string => $revoked,
            self::NOW,
        );

        $this->assertSame([], $responses);
    }

    public function testFetchOcspDiscardsAGoodAnswerFromBehindARevokedOne(): void
    {
        // A CA whose AIA names a load-balanced pair, one of which lags. A revoked
        // verdict discards the material for the whole certificate, as
        // Ocsp\Client::parseResponse() applies the rule among the entries of one
        // response.
        $certId = $this->ocsp->build($this->caDer, $this->leafDer)->certId;
        $revoked = $this->der->ocspResponse(
            $certId,
            "\xA1" . $this->asn1->encodeLength(17) . $this->der->generalizedTime(1_700_000_000),
        );
        $good = $this->der->ocspResponse($certId);

        $skips = [];
        $responses = $this->material->fetchOcsp(
            $this->caDer,
            $this->leafDer,
            ['http://a.example', 'http://b.example'],
            static fn(string $url, string $_request): string => $url === 'http://a.example' ? $revoked : $good,
            self::NOW,
            static function (string $source, string $url, string $_reason, SkipReason $code) use (&$skips): void {
                $skips[] = $source . ' ' . $url . ' ' . $code->value;
            },
        );

        $this->assertSame([], $responses);
        $this->assertSame(['ocsp http://a.example ' . SkipReason::Revoked->value], $skips);
    }

    public function testFetchOcspDiscardsAGoodAnswerFromAheadOfARevokedOne(): void
    {
        // The same with the list the other way round, so the result does not depend
        // on which URL the extension names first.
        $certId = $this->ocsp->build($this->caDer, $this->leafDer)->certId;
        $revoked = $this->der->ocspResponse(
            $certId,
            "\xA1" . $this->asn1->encodeLength(17) . $this->der->generalizedTime(1_700_000_000),
        );
        $good = $this->der->ocspResponse($certId);

        $this->assertSame(
            [],
            $this->material->fetchOcsp(
                $this->caDer,
                $this->leafDer,
                ['http://a.example', 'http://b.example'],
                static fn(string $url, string $_request): string => $url === 'http://b.example' ? $revoked : $good,
                self::NOW,
            ),
        );
    }

    public function testFetchOcspReturnsEmptyWhenNoUrls(): void
    {
        $calls = 0;
        $transport = static function () use (&$calls): string {
            ++$calls;
            return 'X';
        };

        $this->assertSame([], $this->material->fetchOcsp($this->caDer, $this->leafDer, [], $transport));
        $this->assertSame(0, $calls);
    }

    public function testFetchOcspReportsATransportThatAnswersWithNothing(): void
    {
        $skipped = [];
        $responses = $this->material->fetchOcsp(
            $this->caDer,
            $this->leafDer,
            ['http://ocsp.example'],
            static fn(string $_url, string $_request): bool => false,
            self::NOW,
            static function (string $source, string $url, string $reason) use (&$skipped): void {
                $skipped[] = [$source, $url, $reason];
            },
        );

        $this->assertSame([], $responses);
        $this->assertSame([['ocsp', 'http://ocsp.example', 'The transport returned no data']], $skipped);
    }

    public function testFetchCrlDeduplicatesAndSkipsEmpty(): void
    {
        $crl = $this->der->crl();
        $transport = static function (string $url) use ($crl): string {
            if (\str_contains($url, 'empty')) {
                return '';
            }

            return $crl;
        };

        $skipped = [];
        $responses = $this->material->fetchCrl(
            ['http://empty.example', 'http://a.example', 'http://b.example'],
            $transport,
            $this->caDer,
            null,
            self::NOW,
            static function (string $source, string $url, string $reason) use (&$skipped): void {
                $skipped[] = [$source, $url, $reason];
            },
        );

        // Empty response skipped; the two identical CRLs collapse to one.
        $this->assertSame([$crl], $responses);
        $this->assertSame(
            [
                ['crl', 'http://empty.example', 'Empty CRL'],
                ['crl', 'http://b.example',     'Duplicate of an earlier response'],
            ],
            $skipped,
        );
    }

    public function testFetchCrlRejectsBytesThatAreNotACrl(): void
    {
        // An HTTP error body from a distribution point is not revocation evidence.
        $transport = static fn(string $_url): string => '<html>404 Not Found</html>';

        $skipped = [];
        $responses = $this->material->fetchCrl(
            ['http://crl.example'],
            $transport,
            $this->caDer,
            null,
            self::NOW,
            static function (string $_source, string $_url, string $reason) use (&$skipped): void {
                $skipped[] = $reason;
            },
        );

        $this->assertSame([], $responses);
        $this->assertCount(1, $skipped);
    }

    public function testFetchCrlRejectsACrlFromAnotherAuthority(): void
    {
        $crl = $this->der->crl(issuer: (new Asn1())->encodeSequence(''));
        $transport = static fn(string $_url): string => $crl;

        $this->assertSame(
            [],
            $this->material->fetchCrl(['http://crl.example'], $transport, $this->caDer, null, self::NOW),
        );
    }

    public function testFetchCrlRejectsAnExpiredCrl(): void
    {
        $crl = $this->der->crl(self::NOW - 7200, self::NOW - 3600);
        $transport = static fn(string $_url): string => $crl;

        $this->assertSame(
            [],
            $this->material->fetchCrl(['http://crl.example'], $transport, $this->caDer, null, self::NOW),
        );
    }

    public function testFetchCrlRejectsACrlWithABrokenSignature(): void
    {
        // Signed by a key that is not the issuer's.
        $crl = $this->der->crl(signer: Authority::ltv());
        $transport = static fn(string $_url): string => $crl;

        $this->assertSame(
            [],
            $this->material->fetchCrl(['http://crl.example'], $transport, $this->caDer, null, self::NOW),
        );
    }

    public function testFetchCrlReportsARevokedSubjectWithItsOwnCode(): void
    {
        $subject = Authority::leaf()->certDer;
        $serial = (new Certificate($this->asn1))->fields($subject)['serial'];
        $revoked = $this->asn1->encodeSequence($this->asn1->encodeSequence(
            $serial . $this->der->generalizedTime(self::NOW - 3600),
        ));

        $tbs = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(1)
            . $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID) . $this->asn1->encodeNull(),
            )
            . Authority::ocsp()->subject($this->asn1)
            . $this->der->generalizedTime(self::NOW - 3600)
            . $this->der->generalizedTime(1_900_000_000)
            . $revoked,
        );

        $crl = $this->asn1->encodeSequence(
            $tbs
                . $this->asn1->encodeSequence(
                    $this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID) . $this->asn1->encodeNull(),
                )
                . $this->der->bitString(Authority::ocsp()->sign($tbs)),
        );

        $skips = [];
        $result = $this->material->fetchCrl(
            ['http://crl.example'],
            static fn(string $_url): string => $crl,
            $this->caDer,
            $subject,
            self::NOW,
            static function (string $source, string $_url, string $_reason, SkipReason $code) use (&$skips): void {
                $skips[] = [$source, $code];
            },
        );

        $this->assertSame([], $result);
        $this->assertSame([['crl', SkipReason::Revoked]], $skips);
    }

    public function testFetchCrlDistinguishesAnUnreachableUrlFromARejectedAnswer(): void
    {
        $codes = [];
        $observer = static function (string $_source, string $_url, string $_reason, SkipReason $code) use (
            &$codes,
        ): void {
            $codes[] = $code;
        };

        // A transport failure is Unreachable; a CRL from another authority arrived
        // and was refused, which is Invalid.
        $this->material->fetchCrl(
            ['http://crl.example'],
            static fn(string $_url): string => throw new \RuntimeException('Connection timed out'),
            $this->caDer,
            null,
            self::NOW,
            $observer,
        );

        $foreign = $this->der->crl(signer: Authority::ltv());
        $this->material->fetchCrl(
            ['http://crl.example'],
            static fn(string $_url): string => $foreign,
            $this->caDer,
            null,
            self::NOW,
            $observer,
        );

        $this->assertSame([SkipReason::Unreachable, SkipReason::Invalid], $codes);
    }

    public function testReportNotAttemptedNamesEveryUrl(): void
    {
        $skips = [];
        $this->material->reportNotAttempted(
            'crl',
            ['http://a.example', 'http://b.example'],
            'no issuer',
            static function (string $source, string $url, string $reason, SkipReason $code) use (&$skips): void {
                $skips[] = [$source, $url, $reason, $code];
            },
        );

        $this->assertSame(
            [
                ['crl', 'http://a.example', 'no issuer', SkipReason::NotAttempted],
                ['crl', 'http://b.example', 'no issuer', SkipReason::NotAttempted],
            ],
            $skips,
        );
    }

    public function testReportNotAttemptedWithoutAnObserverIsANoOp(): void
    {
        $this->material->reportNotAttempted('crl', ['http://a.example'], 'no issuer', null);
        $this->addToAssertionCount(1);
    }
}
