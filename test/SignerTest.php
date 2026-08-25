<?php

declare(strict_types=1);

/**
 * SignerTest.php
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

namespace Test;

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Builder;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Cms\SigningRequest;
use Com\Tecnick\Pdf\Sign\Config;
use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Ltv\SkipReason;
use Com\Tecnick\Pdf\Sign\Ocsp\Client as OcspClient;
use Com\Tecnick\Pdf\Sign\SignatureProfile;
use Com\Tecnick\Pdf\Sign\Signer;
use Com\Tecnick\Pdf\Sign\Timestamp\Client as TimestampClient;
use Com\Tecnick\Pdf\Sign\Timestamp\Config as TimestampConfig;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Credentials;
use Test\Fixture\Der;

/**
 * Signer Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Signer::class)]
final class SignerTest extends TestCase
{
    /**
     * A moment inside the validity interval the fixture responses declare.
     */
    private const NOW = 1_800_000_000;

    private const SIGNING_TIME = 1_700_000_000;

    private const OID_SIGNATURE_TIMESTAMP = '1.2.840.113549.1.9.16.2.14';

    private const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';

    private Asn1 $asn1;

    private Der $der;

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->der = new Der($this->asn1);
    }

    /**
     * A transport that answers a TimeStampReq with a token that matches it.
     *
     * @param string|null  $captured Receives the DER request that was sent.
     * @param list<string>  $certsDer Certificates to embed in the returned token.
     *
     * @return callable(string): string
     */
    private function timestampTransport(?string &$captured = null, array $certsDer = []): callable
    {
        return function (string $request) use (&$captured, $certsDer): string {
            $captured = $request;
            [$imprint, $hashOid, $nonce] = $this->requestFields($request);

            return $this->der->timestampResponse(0, $this->der->signedTimestampToken(
                $this->der->tstInfo($imprint, $hashOid, $nonce),
                $certsDer,
            ));
        };
    }

    /**
     * Recover the imprint, digest OID, and nonce from a DER TimeStampReq.
     *
     * @return array{string, string, string}
     */
    private function requestFields(string $der): array
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

        return [$hashed['value'], $this->asn1->decodeObjectIdentifier($oid['value']), $nonce];
    }

    public function testSignLegacyProfileHasNoSignatureTimestamp(): void
    {
        $cred = $this->makeCredential();
        $signer = new Signer();

        $cms = $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_LEGACY),
            self::SIGNING_TIME,
        );

        $this->assertStringNotContainsString($this->timestampOidDer(), $cms);
        // The legacy (ISO 32000-1) profile keeps the CMS signing-time attribute.
        $this->assertStringContainsString($this->signingTimeOidDer(), $cms);
    }

    public function testSignBbProfileHasNoSignatureTimestamp(): void
    {
        $cred = $this->makeCredential();
        $signer = new Signer();

        $cms = $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_PADES_B_B),
            self::SIGNING_TIME,
        );

        $this->assertStringNotContainsString($this->timestampOidDer(), $cms);
        // PAdES-BASELINE forbids the CMS signing-time attribute (ETSI EN 319 142-1);
        // the signing time is carried by the /M signature dictionary entry instead.
        $this->assertStringNotContainsString($this->signingTimeOidDer(), $cms);
    }

    public function testSignBtProfileEmbedsSignatureTimestamp(): void
    {
        $cred = $this->makeCredential();

        $captured = null;
        $transport = $this->timestampTransport($captured);

        $signer = new Signer();
        $cms = $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_PADES_B_T),
            self::SIGNING_TIME,
            new TimestampClient(new TimestampConfig('https://tsa.example.org')),
            $transport,
            timestampNow: self::SIGNING_TIME,
        );

        // The transport received a DER TimeStampReq (SEQUENCE).
        $this->assertIsString($captured);
        $this->assertSame("\x30", $captured[0]);

        // The CMS carries the signature-timestamp attribute.
        $this->assertStringContainsString($this->timestampOidDer(), $cms);
    }

    public function testSignatureTimestampTokensFeedTheValidationMaterialCollector(): void
    {
        // The token is produced inside sign(), by a provider the host does not hold,
        // and the transport sees the TimeStampResp rather than the token inside it.
        $cred = $this->makeCredential();

        $signer = new Signer();
        $cms = $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_PADES_B_T),
            self::SIGNING_TIME,
            new TimestampClient(new TimestampConfig('https://tsa.example.org')),
            $this->timestampTransport(),
            timestampNow: self::SIGNING_TIME,
        );

        $tokens = $signer->signatureTimestampTokens($cms);
        $this->assertCount(1, $tokens);

        // The recovered bytes are the token, so the collector accepts them and adds
        // the TSA's own certificate to the material.
        $material = $signer->collectValidationMaterial(
            [Authority::ltvLeaf()->certPem, Authority::ltv()->certPem],
            null,
            null,
            $tokens,
            self::SIGNING_TIME,
        );

        $this->assertContains(Authority::tsa()->certDer, $material['certs']);
    }

    public function testSignatureTimestampTokensIsEmptyWithoutATimestamp(): void
    {
        $cred = $this->makeCredential();

        $signer = new Signer();
        $cms = $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_PADES_B_B),
            self::SIGNING_TIME,
        );

        $this->assertSame([], $signer->signatureTimestampTokens($cms));
    }

    public function testSignBtProfileRejectsATokenForOtherBytes(): void
    {
        $cred = $this->makeCredential();

        // A TSA (or a MITM) answering with a token over unrelated bytes.
        $unrelated = $this->der->timestampResponse(
            0,
            $this->der->timestampToken($this->der->tstInfo(
                \hash('sha256', 'other bytes', true),
                '2.16.840.1.101.3.4.2.1',
            )),
        );

        $signer = new Signer();

        $this->expectException(Exception::class);
        $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_PADES_B_T),
            self::SIGNING_TIME,
            new TimestampClient(new TimestampConfig('https://tsa.example.org')),
            static fn(string $_request): string => $unrelated,
        );
    }

    public function testSignBtProfileRequiresTimestampClient(): void
    {
        $cred = $this->makeCredential();
        $signer = new Signer();

        $this->expectException(Exception::class);
        $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_PADES_B_T),
            self::SIGNING_TIME,
        );
    }

    public function testSignBltaProfileRequiresTransport(): void
    {
        $cred = $this->makeCredential();
        $signer = new Signer();

        $this->expectException(Exception::class);
        $signer->sign(
            'document bytes',
            $cred['cert_der'],
            $cred['key'],
            [],
            new Config(Config::PROFILE_PADES_B_LTA),
            self::SIGNING_TIME,
            new TimestampClient(new TimestampConfig('https://tsa.example.org')),
            null,
        );
    }

    public function testPrepareKeepsSigningTimeForTheLegacyProfile(): void
    {
        $cred = $this->makeCredential();
        $signer = new Signer();

        $request = $signer->prepare(
            \hash('sha256', 'document bytes', true),
            $cred['cert_der'],
            new Config(Config::PROFILE_LEGACY),
            self::SIGNING_TIME,
        );

        $this->assertTrue($request->includeSigningTime);
        $this->assertSame('sha256', $request->digestAlgorithm);
        $this->assertSame(self::SIGNING_TIME, $request->signingTime);
    }

    public function testPrepareOmitsSigningTimeForPadesProfiles(): void
    {
        $cred = $this->makeCredential();
        $signer = new Signer();

        foreach ([Config::PROFILE_PADES_B_B, Config::PROFILE_PADES_B_T, Config::PROFILE_PADES_B_LTA] as $profile) {
            $request = $signer->prepare(
                \hash('sha384', 'document bytes', true),
                $cred['cert_der'],
                new Config($profile, 'sha384'),
                self::SIGNING_TIME,
            );

            $this->assertFalse($request->includeSigningTime);
            $this->assertSame('sha384', $request->digestAlgorithm);
        }
    }

    public function testAssembleReproducesSignForTheBbProfile(): void
    {
        $cred = $this->makeCredential();
        $config = new Config(Config::PROFILE_PADES_B_B);
        $signer = new Signer();
        $builder = new Builder($this->asn1);

        $signed = $signer->sign('document bytes', $cred['cert_der'], $cred['key'], [], $config, self::SIGNING_TIME);

        $request = $signer->prepare(
            \hash('sha256', 'document bytes', true),
            $cred['cert_der'],
            $config,
            self::SIGNING_TIME,
        );
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $this->assertSame($signed, $signer->buildFromSignature($request, $signature, [], $config));
    }

    public function testAssembleBtProfileEmbedsSignatureTimestamp(): void
    {
        $cred = $this->makeCredential();
        $config = new Config(Config::PROFILE_PADES_B_T);
        $transport = $this->timestampTransport();

        $signer = new Signer();
        $builder = new Builder($this->asn1);

        $request = $signer->prepare(
            \hash('sha256', 'document bytes', true),
            $cred['cert_der'],
            $config,
            self::SIGNING_TIME,
        );
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $cms = $signer->buildFromSignature(
            $request,
            $signature,
            [],
            $config,
            new TimestampClient(new TimestampConfig('https://tsa.example.org')),
            $transport,
            timestampNow: self::SIGNING_TIME,
        );

        $this->assertStringContainsString($this->timestampOidDer(), $cms);
        $this->assertStringNotContainsString($this->signingTimeOidDer(), $cms);
    }

    public function testBuildFromSignatureRejectsARequestPreparedForAnotherProfile(): void
    {
        // The signing-time rule is fixed at prepare() time and the CMS is rebuilt
        // from the request, so the two halves of a two-phase signature are compared
        // rather than reapplied.
        $cred = $this->makeCredential();
        $signer = new Signer();

        $request = $signer->prepare(
            \hash('sha256', 'document bytes', true),
            $cred['cert_der'],
            new Config(Config::PROFILE_LEGACY),
            self::SIGNING_TIME,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/prepared for another profile/');
        $signer->buildFromSignature($request, 'signature', [], new Config(Config::PROFILE_PADES_B_B));
    }

    public function testBuildFromSignatureRejectsARequestPreparedWithAnotherDigest(): void
    {
        $cred = $this->makeCredential();
        $signer = new Signer();

        $request = $signer->prepare(
            \hash('sha512', 'document bytes', true),
            $cred['cert_der'],
            new Config(Config::PROFILE_PADES_B_B, 'sha512'),
            self::SIGNING_TIME,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/prepared with sha512, not sha256/');
        $signer->buildFromSignature($request, 'signature', [], new Config(Config::PROFILE_PADES_B_B));
    }

    public function testBuildFromSignatureBltProfileRequiresTimestampClientAndTransport(): void
    {
        $cred = $this->makeCredential();
        $config = new Config(Config::PROFILE_PADES_B_LT);
        $signer = new Signer();

        $request = $signer->prepare(
            \hash('sha256', 'document bytes', true),
            $cred['cert_der'],
            $config,
            self::SIGNING_TIME,
        );

        // Asserted by message, the missing-transport check and the signature check
        // being otherwise indistinguishable.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/requires a timestamp client and transport/');
        $signer->buildFromSignature($request, 'signature', [], $config);
    }

    public function testAssembleRejectsASignatureThatDoesNotVerify(): void
    {
        $cred = $this->makeCredential();
        $config = new Config(Config::PROFILE_PADES_B_B);
        $signer = new Signer();

        $request = $signer->prepare(
            \hash('sha256', 'document bytes', true),
            $cred['cert_der'],
            $config,
            self::SIGNING_TIME,
        );

        $this->expectException(Exception::class);
        $signer->buildFromSignature($request, 'not a signature', [], $config);
    }

    public function testSignaturePayloadMatchesTheBuilder(): void
    {
        // The two-phase flow completes through Signer alone.
        $cred = $this->makeCredential();
        $signer = new Signer();
        $config = new Config(Config::PROFILE_PADES_B_B);

        $request = $signer->prepare(
            \hash('sha256', 'document bytes', true),
            $cred['cert_der'],
            $config,
            self::SIGNING_TIME,
        );

        $payload = $signer->signaturePayload($request);
        $this->assertSame((new Builder($this->asn1))->signaturePayload($request), $payload);

        // The payload is the DER SET OF signed attributes, as RFC 5652 section 5.4 requires.
        $offset = 0;
        $set = $this->asn1->readTlv($payload, $offset);
        $this->assertSame(0x31, $set['tag']);
        $this->assertSame(\strlen($payload), $offset);

        $signature = '';
        \openssl_sign($payload, $signature, $cred['key'], OPENSSL_ALGO_SHA256);
        $this->assertNotSame('', $signer->buildFromSignature($request, $signature, [], $config));
    }

    public function testCollectValidationMaterialGathersCertsOcspAndCrls(): void
    {
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        // The ltv chain's own CA signs the fixture responses, since the codecs verify
        // them against the issuer the chain names.
        $der = new Der($this->asn1, Authority::ltv());
        $ocsp = new OcspClient($this->asn1);
        $response = $der->ocspResponse($ocsp->build(
            Certificate::pemToDer($caPem),
            Certificate::pemToDer($ltvPem),
        )->certId);
        $crl = $der->crl();

        $ocspCalls = [];
        $ocspTransport = static function (string $url, string $request) use (&$ocspCalls, $response): string {
            $ocspCalls[] = ['url' => $url, 'request' => $request];
            return $response;
        };
        $crlTransport = static fn(string $_url): string => $crl;

        $signer = new Signer();
        $material = $signer->collectValidationMaterial([$ltvPem, $caPem], $ocspTransport, $crlTransport, [], self::NOW);

        // Both certificates are collected as DER.
        $this->assertCount(2, $material['certs']);

        // The leaf's single OCSP responder was queried; the CA has none.
        $this->assertCount(1, $ocspCalls);
        $firstOcspCall = $ocspCalls[0] ?? null;
        if (!\is_array($firstOcspCall)) {
            $this->fail('Expected a captured OCSP call');
        }

        $this->assertSame('http://ocsp.example.org/r', $firstOcspCall['url']);
        $this->assertSame("\x30", $firstOcspCall['request'][0]);
        $this->assertSame([$response], $material['ocsp']);

        // The leaf carries two distinct CRL distribution points, which answer with the
        // same list, so it is collected once.
        $this->assertSame([$crl], $material['crls']);
    }

    public function testCollectValidationMaterialSkipsRevocationWithoutTransports(): void
    {
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $signer = new Signer();
        $material = $signer->collectValidationMaterial([$ltvPem, $caPem]);

        $this->assertCount(2, $material['certs']);
        $this->assertSame([], $material['ocsp']);
        $this->assertSame([], $material['crls']);
    }

    public function testCollectValidationMaterialDeduplicatesCertificates(): void
    {
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        // The root is self-issued, so repeating it keeps the chain ordered while
        // giving the deduplication something to collapse.
        $signer = new Signer();
        $material = $signer->collectValidationMaterial([$ltvPem, $caPem, $caPem]);

        $this->assertCount(2, $material['certs']);
    }

    public function testCollectValidationMaterialRejectsAMisorderedChain(): void
    {
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        // Root first: OCSP built from this order would ask the leaf about the root.
        $signer = new Signer();

        $this->expectException(Exception::class);
        $signer->collectValidationMaterial([$caPem, $ltvPem]);
    }

    public function testCollectValidationMaterialAddsTimestampCertificates(): void
    {
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');
        $tsaCert = Authority::tsa()->certDer;

        $token = $this->der->signedTimestampToken($this->der->tstInfo(
            \hash('sha256', 'signature', true),
            '2.16.840.1.101.3.4.2.1',
        ));

        // ETSI EN 319 142-1: a B-LT DSS covers the signature timestamp path too.
        $signer = new Signer();
        $material = $signer->collectValidationMaterial([$ltvPem, $caPem], null, null, [$token]);

        $this->assertCount(3, $material['certs']);
        $this->assertContains($tsaCert, $material['certs']);
    }

    public function testCollectValidationMaterialCollectsRevocationForTheTimestampChain(): void
    {
        // ETSI EN 319 142-1: a B-LT DSS covers the signature timestamp's validation
        // path, and the TSA certificates alone do not show they were not revoked.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        // A TSA leaf issued by the ltv CA, so the token carries a real two-entry path
        // and the leaf's AIA names a responder.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [Certificate::pemToDer($caPem)],
            Authority::ltvLeaf(),
        );

        $ocspUrls = [];
        $ocspTransport = static function (string $url) use (&$ocspUrls): bool {
            $ocspUrls[] = $url;
            return false;
        };

        $signer = new Signer();
        $signer->collectValidationMaterial([$ltvPem, $caPem], $ocspTransport, null, [$token], self::NOW);

        // Once for the signer's own chain and once for the timestamp path.
        $this->assertSame(['http://ocsp.example.org/r', 'http://ocsp.example.org/r'], $ocspUrls);
    }

    public function testCollectValidationMaterialOrdersAnUnorderedTimestampCertificateSet(): void
    {
        // A CMS CertificateSet has no order, so the TSA certificates arrive as a bag
        // and have to be sorted into a path before any lookup can be built.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $urls = [];
        $crlTransport = static function (string $url) use (&$urls): bool {
            $urls[] = $url;
            return false;
        };

        // Root first in the token, which is the order a validator must not rely on.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [Certificate::pemToDer($caPem)],
            Authority::ltvLeaf(),
        );

        $signer = new Signer();
        $signer->collectValidationMaterial([$ltvPem, $caPem], null, $crlTransport, [$token], self::NOW);

        // The self-signed root's own CRL is skipped at both ends, so only the leaf's
        // two distribution points are queried, twice.
        $this->assertSame(
            [
                'http://crl.example.org/root.crl',
                'http://crl2.example.org/root.crl',
                'http://crl.example.org/root.crl',
                'http://crl2.example.org/root.crl',
            ],
            $urls,
        );
    }

    public function testCollectValidationMaterialKeepsTimestampCertificatesThatDoNotChain(): void
    {
        // A CertificateSet may carry certificates from more than one path. Those
        // that do not chain are still collected, though no revocation lookup can be
        // built for them.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');
        $unrelated = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/data/ocsp_leaf.pem'));
        $alsoUnrelated = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/data/ocsp_responder.pem'));

        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [$unrelated, $alsoUnrelated],
        );

        $signer = new Signer();
        $material = $signer->collectValidationMaterial([$ltvPem, $caPem], null, null, [$token], self::NOW);

        $this->assertContains($unrelated, $material['certs']);
        $this->assertContains($alsoUnrelated, $material['certs']);
    }

    public function testCollectValidationMaterialIgnoresTheOrderOfTheTimestampBag(): void
    {
        // The certificates field sits outside signedAttrs and is covered by no
        // signature, so the path is anchored at the certificate that signed the token
        // rather than at a leaf picked out of the bag.
        $caDer = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem'));
        $alien = Authority::ocsp()->certDer;

        /** @return list<string> */
        $collect = function (string ...$extraCerts): array {
            $urls = [];
            $token = $this->der->signedTimestampToken(
                $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
                \array_values($extraCerts),
                Authority::ltvLeaf(),
            );

            (new Signer())->collectValidationMaterial(
                [],
                static function (string $url) use (&$urls): bool {
                    $urls[] = $url;
                    return false;
                },
                null,
                [$token],
                self::NOW,
            );

            return $urls;
        };

        $this->assertSame($collect($caDer), $collect($alien, $caDer));
        $this->assertSame(['http://ocsp.example.org/r'], $collect($alien, $caDer));
    }

    public function testCollectValidationMaterialReportsBagMembersOutsideTheTimestampPath(): void
    {
        // A member that chains to nothing is embedded but not looked up, and its
        // URLs are reported instead. The token is signed by the TSA of the ocsp CA, so
        // the path is those two; ltv_cert belongs to another authority and is the one
        // fixture carrying an AIA.
        $stray = Authority::ltvLeaf()->certDer;

        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [Authority::ocsp()->certDer, $stray],
        );

        $skips = [];
        $material = (new Signer())->collectValidationMaterial(
            [],
            static fn(string $_url, string $_request): bool => false,
            null,
            [$token],
            self::NOW,
            static function (string $source, string $url, string $_reason, SkipReason $code) use (&$skips): void {
                $skips[] = [$source, $url, $code];
            },
        );

        $this->assertContains($stray, $material['certs']);
        $this->assertSame([['ocsp', 'http://ocsp.example.org/r', SkipReason::NotAttempted]], $skips);
    }

    public function testCollectValidationMaterialWillNotEmbedABagMemberThatIsNotACertificate(): void
    {
        // The bag is unauthenticated and what it holds is written into the /Certs
        // array, so every member has to parse as a certificate.
        $junk = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(0) . $this->asn1->encodeOctetString('not a certificate'),
        );

        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [$junk],
        );

        $material = (new Signer())->collectValidationMaterial([], null, null, [$token], self::NOW);

        $this->assertSame([Authority::tsa()->certDer], $material['certs']);
    }

    public function testCollectValidationMaterialAcceptsATokenWithJunkAheadOfTheSignerCertificate(): void
    {
        // The same member placed before the signer certificate is passed over rather
        // than ending the search for it.
        $junk = $this->asn1->encodeSequence($this->asn1->encodeInteger(7));
        $tsaDer = Authority::tsa()->certDer;

        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [$junk],
        );

        $reordered = \str_replace($tsaDer . $junk, $junk . $tsaDer, $token);
        $this->assertNotSame($token, $reordered, 'the bag was not reordered');

        $material = (new Signer())->collectValidationMaterial([], null, null, [$reordered], self::NOW);

        $this->assertSame([$tsaDer], $material['certs']);
    }

    public function testCollectValidationMaterialRejectsATimestampTokenThatDoesNotVerify(): void
    {
        // The path is anchored at the certificate the token was verified against, so
        // a token that verifies against nothing it embeds anchors nothing.
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [],
            null,
            false,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not embed the signer certificate/');
        (new Signer())->collectValidationMaterial([], null, null, [$token], self::NOW);
    }

    public function testCollectValidationMaterialAcceptsAChainGivenAsDer(): void
    {
        // Either encoding is accepted, so one chain serves sign() and the
        // collector.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $signer = new Signer();
        $fromPem = $signer->collectValidationMaterial([$ltvPem, $caPem]);
        $fromDer = $signer->collectValidationMaterial([Certificate::pemToDer($ltvPem), Certificate::pemToDer($caPem)]);

        $this->assertSame($fromPem, $fromDer);
    }

    public function testCollectValidationMaterialRejectsAChainEntryThatIsNotACertificate(): void
    {
        // A private key file passed where a chain was meant is refused rather than
        // returned in 'certs'.
        $this->expectException(Exception::class);
        (new Signer())->collectValidationMaterial([(string) \file_get_contents(__DIR__ . '/data/ltv_cert.key')]);
    }

    public function testCollectValidationMaterialReportsSkippedUrls(): void
    {
        // Every skipped URL is reported through the observer.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $skipped = [];
        $signer = new Signer();
        $material = $signer->collectValidationMaterial(
            [$ltvPem, $caPem],
            static fn(string $_url, string $_request): string => 'not an OCSP response',
            static fn(string $_url): string => 'not a CRL',
            [],
            self::NOW,
            static function (string $source, string $url, string $reason) use (&$skipped): void {
                $skipped[] = $source . ' ' . $url . ': ' . $reason;
            },
        );

        $this->assertSame([], $material['ocsp']);
        $this->assertSame([], $material['crls']);
        $this->assertCount(3, $skipped);
        $this->assertStringStartsWith('ocsp http://ocsp.example.org/r: ', $skipped[0] ?? '');
        $this->assertStringStartsWith('crl http://crl.example.org/root.crl: ', $skipped[1] ?? '');
    }

    public function testCollectValidationMaterialWillNotEmbedACrlItCannotAttribute(): void
    {
        // A chain that stops below the root leaves its topmost entry with no issuer
        // certificate, and a CRL nobody can attribute is not evidence, so no lookup
        // is attempted for it.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');

        // Signed by an unrelated key, naming an unrelated issuer, currently valid.
        $forged = $this->der->crl(self::NOW - 3600, self::NOW + 86_400, null, Authority::ocsp());

        $skipped = [];
        $material = (new Signer())->collectValidationMaterial(
            [$ltvPem],
            null,
            static fn(string $_url): string => $forged,
            [],
            self::NOW,
            static function (string $source, string $url, string $_reason, SkipReason $code) use (&$skipped): void {
                $skipped[] = [$source, $url, $code];
            },
        );

        $this->assertSame([], $material['crls']);
        $this->assertSame(
            [
                ['crl', 'http://crl.example.org/root.crl',  SkipReason::NotAttempted],
                ['crl', 'http://crl2.example.org/root.crl', SkipReason::NotAttempted],
            ],
            $skipped,
        );
    }

    public function testCollectValidationMaterialWillNotAttemptOcspWithoutAnIssuer(): void
    {
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');

        $skipped = [];
        $material = (new Signer())->collectValidationMaterial(
            [$ltvPem],
            static fn(string $_url, string $_request): string => 'never reached',
            null,
            [],
            self::NOW,
            static function (string $source, string $_url, string $_reason, SkipReason $code) use (&$skipped): void {
                $skipped[] = [$source, $code];
            },
        );

        $this->assertSame([], $material['ocsp']);
        $this->assertSame([['ocsp', SkipReason::NotAttempted]], $skipped);
    }

    public function testCollectValidationMaterialSaysNothingAboutASelfSignedRoot(): void
    {
        // The trust anchor's own revocation material is not fetched and not
        // reported.
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $skipped = [];
        (new Signer())->collectValidationMaterial(
            [$caPem],
            static fn(string $_url, string $_request): string => 'x',
            static fn(string $_url): string => 'x',
            [],
            self::NOW,
            static function (string $_source, string $_url, string $_reason, SkipReason $code) use (&$skipped): void {
                $skipped[] = $code;
            },
        );

        $this->assertSame([], $skipped);
    }

    public function testCollectValidationMaterialReportsARevokedSignerWithItsOwnCode(): void
    {
        // The code separates a revoked verdict from an unreachable responder.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $ocsp = new OcspClient($this->asn1);
        $request = $ocsp->build(Certificate::pemToDer($caPem), Certificate::pemToDer($ltvPem));
        $revoked = $this->asn1->encodeContext(1, $this->der->generalizedTime(self::NOW - 86_400));
        $der = new Der($this->asn1, Authority::ltv());
        $response = $der->ocspResponse($request->certId, $revoked, self::NOW - 3600);

        $codes = [];
        $material = (new Signer())->collectValidationMaterial(
            [$ltvPem, $caPem],
            static fn(string $_url, string $_request): string => $response,
            null,
            [],
            self::NOW,
            static function (string $_source, string $_url, string $_reason, SkipReason $code) use (&$codes): void {
                $codes[] = $code;
            },
        );

        $this->assertSame([], $material['ocsp']);
        $this->assertSame([SkipReason::Revoked], $codes);
    }

    public function testCollectValidationMaterialDiscardsTheCrlOfACertificateOcspReportedRevoked(): void
    {
        // A revoked verdict belongs to the certificate rather than to the source that
        // returned it, so a verdict from either source discards both.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $ocsp = new OcspClient($this->asn1);
        $request = $ocsp->build(Certificate::pemToDer($caPem), Certificate::pemToDer($ltvPem));
        $revoked = $this->asn1->encodeContext(1, $this->der->generalizedTime(self::NOW - 86_400));
        $der = new Der($this->asn1, Authority::ltv());
        $response = $der->ocspResponse($request->certId, $revoked, self::NOW - 3600);
        $crl = $der->crl(self::NOW - 3600, self::NOW + 86_400, null, Authority::ltv());

        $material = (new Signer())->collectValidationMaterial(
            [$ltvPem, $caPem],
            static fn(string $_url, string $_request): string => $response,
            static fn(string $_url): string => $crl,
            [],
            self::NOW,
        );

        $this->assertSame([], $material['ocsp']);
        $this->assertSame([], $material['crls']);
    }

    public function testCollectValidationMaterialReportsASelfIssuedCertificateThatIsNotSelfSigned(): void
    {
        // RFC 5280 separates self-issued, where the subject and issuer Names are
        // equal, from self-signed, where the certificate's own key signed it. A CA key
        // rollover certificate is the first without being the second, so it is not a
        // trust anchor and its skipped URLs are reported.
        $rolloverPem = (string) \file_get_contents(__DIR__ . '/data/ltv_rollover.pem');

        $skipped = [];
        (new Signer())->collectValidationMaterial(
            [$rolloverPem],
            static fn(string $_url, string $_request): string => 'x',
            static fn(string $_url): string => 'x',
            [],
            self::NOW,
            static function (string $source, string $url, string $_reason, SkipReason $code) use (&$skipped): void {
                $skipped[] = [$source, $url, $code];
            },
        );

        $this->assertSame(
            [
                ['ocsp', 'http://ocsp.example.org/r',       SkipReason::NotAttempted],
                ['crl',  'http://crl.example.org/root.crl', SkipReason::NotAttempted],
            ],
            $skipped,
        );
    }

    public function testCollectValidationMaterialRejectsAChainEntryThatIsNotAString(): void
    {
        // Typed loosely on purpose: a member that is not a string would reach
        // Certificate::toDer() as a TypeError rather than an Exception.
        /** @var list<string> $chain */
        $chain = [42];

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid chain certificate 0/');
        (new Signer())->collectValidationMaterial($chain);
    }

    public function testCollectValidationMaterialRejectsATimestampTokenThatIsNotAString(): void
    {
        // The other list this method takes, held to the same reading as the chain: a
        // member that is not a string would reach boundedTokenCertificates() as a
        // TypeError rather than an Exception.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        /** @var list<string> $tokens */
        $tokens = [42];

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid timestamp token 0/');
        (new Signer())->collectValidationMaterial([$ltvPem, $caPem], null, null, $tokens);
    }

    public function testEveryTimestampedProfileRequiresATimestampClient(): void
    {
        // Signer::TIMESTAMPED_PROFILES is a second list of profiles and
        // SignatureProfile is the closed set, so the two are pinned together as
        // SignatureProfileTest pins Config::PROFILES.
        $cred = $this->makeCredential();

        foreach (SignatureProfile::values() as $profile) {
            $config = new Config($profile);
            $timestamped = $profile !== Config::PROFILE_LEGACY && $profile !== Config::PROFILE_PADES_B_B;

            try {
                (new Signer())->sign('content', $cred['cert_der'], $cred['key'], [], $config, self::SIGNING_TIME);
                $this->assertFalse($timestamped, $profile . ' signed without a timestamp client');
            } catch (Exception $e) {
                $this->assertTrue($timestamped, $profile . ' refused to sign: ' . $e->getMessage());
                $this->assertStringContainsString('requires a timestamp client and transport', $e->getMessage());
            }
        }
    }

    public function testCollectValidationMaterialOrdersTheTimestampPathBySignature(): void
    {
        // Two authorities may share a subject Name, so the bag is ordered by
        // signature rather than by Name.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        // ocsp_ca is self-signed and issued neither of the ltv certificates, so it
        // cannot become the issuer of the timestamp leaf.
        $impostor = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/data/ocsp_ca.pem'));
        $token = $this->der->signedTimestampToken(
            $this->der->tstInfo(\hash('sha256', 'signature', true), '2.16.840.1.101.3.4.2.1'),
            [$impostor],
            Authority::ltvLeaf(),
        );

        $urls = [];
        (new Signer())->collectValidationMaterial(
            [$ltvPem, $caPem],
            null,
            static function (string $url) use (&$urls): string {
                $urls[] = $url;
                return 'not a CRL';
            },
            [$token],
            self::NOW,
        );

        // The signer's own chain is queried; the timestamp leaf is left alone, the
        // impostor not being its issuer.
        $this->assertSame(['http://crl.example.org/root.crl', 'http://crl2.example.org/root.crl'], $urls);
    }

    public function testCollectValidationMaterialRejectsAChainLinkedByNameOnly(): void
    {
        // Two authorities may share a subject Name, so the chain order is established
        // by signature rather than by Name.
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $impostor = $this->impostorCaPem();

        $signer = new Signer();

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not ordered leaf-first/');
        $signer->collectValidationMaterial([$ltvPem, $impostor]);
    }

    /**
     * A self-signed CA whose subject Name matches the ltv CA but whose key does not.
     */
    private function impostorCaPem(): string
    {
        $config = [
            'config' => __DIR__ . '/../openssl.cnf',
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $subject = [
            'countryName' => 'IT',
            'organizationName' => 'Tecnick.com',
            'commonName' => 'tc-lib-pdf-sign ltv CA',
        ];

        $key = \openssl_pkey_new($config);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            $this->markTestSkipped('RSA key generation is not available');
        }

        $csr = \openssl_csr_new($subject, $key, $config);
        if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
            $this->markTestSkipped('CSR generation failed');
        }

        $cert = \openssl_csr_sign($csr, null, $key, 365, $config);
        if (!$cert instanceof \OpenSSLCertificate) {
            $this->markTestSkipped('Certificate signing failed');
        }

        $pem = '';
        \openssl_x509_export($cert, $pem);

        return $pem;
    }

    public function testCollectValidationMaterialSkipsTheSelfSignedRootCrl(): void
    {
        $ltvPem = (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem');
        $caPem = (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem');

        $urls = [];
        $crlTransport = static function (string $url) use (&$urls): string {
            $urls[] = $url;
            return 'CRL-' . $url;
        };

        $signer = new Signer();
        $signer->collectValidationMaterial([$ltvPem, $caPem], null, $crlTransport);

        // Only the leaf's distribution points are queried; the trust anchor's own
        // CRL is skipped.
        $this->assertSame(['http://crl.example.org/root.crl', 'http://crl2.example.org/root.crl'], $urls);
    }

    public function testCollectValidationMaterialRejectsInvalidPem(): void
    {
        $signer = new Signer();
        $this->expectException(Exception::class);
        $signer->collectValidationMaterial(['-----BEGIN CERTIFICATE-----@@-----END CERTIFICATE-----']);
    }

    public function testCollectValidationMaterialRejectsAChainInOnePemFile(): void
    {
        // fullchain.pem passed as one entry, which is refused rather than decoded as
        // a chain of one.
        $signer = new Signer();

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/more than one certificate/');
        $signer->collectValidationMaterial([
            (string) \file_get_contents(__DIR__ . '/data/ltv_cert.pem')
                . (string) \file_get_contents(__DIR__ . '/data/ltv_ca.pem'),
        ]);
    }

    public function testCollectValidationMaterialAcceptsAnIssuerThatReEncodedItsName(): void
    {
        // The same authority holding the same key, with its Name carried as a
        // PrintableString where the leaf names it as a UTF8String. The signature
        // settles the link, so this is a chain and not a misordered one.
        $leafPem = (string) \file_get_contents(__DIR__ . '/data/ocsp_leaf.pem');
        $reissuedPem = (string) \file_get_contents(__DIR__ . '/data/ocsp_ca_printable.pem');

        $material = (new Signer())->collectValidationMaterial([$leafPem, $reissuedPem]);

        $this->assertSame([Certificate::pemToDer($leafPem), Certificate::pemToDer($reissuedPem)], $material['certs']);
    }

    public function testCollectValidationMaterialRejectsAnOversizedTimestampCertificateBag(): void
    {
        // Ordering a bag of n members costs n^2 signature checks, so a bag larger
        // than MAX_PATH_CERTIFICATES is refused before that work.
        // One over the limit, counting the TSA's own certificate that every signed
        // token carries.
        $token = $this->tokenWithCertificateBag(Signer::MAX_PATH_CERTIFICATES);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/embeds more than 32 certificates: 33/');
        (new Signer())->collectValidationMaterial([], null, null, [$token]);
    }

    public function testCollectValidationMaterialBoundsTheBagBeforeVerifyingTheToken(): void
    {
        // The bag is bounded before the token is verified, since resolving the signer
        // walks it twice more, so a token that fails both checks reports the bag.
        $bag = [];
        for ($i = 0; $i <= Signer::MAX_PATH_CERTIFICATES; ++$i) {
            $member = Authority::leaf()->certDer;
            $member[20] = \chr($i);
            $bag[] = $member;
        }

        // Carries no SignerInfo, so verifying it fails as surely as its bag is oversized.
        $token = $this->der->timestampToken($this->der->tstInfo('imprint', '2.16.840.1.101.3.4.2.1'), $bag);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/embeds more than 32 certificates: 33/');
        (new Signer())->collectValidationMaterial([], null, null, [$token]);
    }

    public function testCollectValidationMaterialAcceptsABagAtTheLimit(): void
    {
        $token = $this->tokenWithCertificateBag(Signer::MAX_PATH_CERTIFICATES - 1);
        $material = (new Signer())->collectValidationMaterial([], null, null, [$token]);

        $this->assertCount(Signer::MAX_PATH_CERTIFICATES, $material['certs']);
    }

    public function testSignRefusesAnExpiredCertificateWhenAskedTo(): void
    {
        $credential = $this->makeCredential();

        $signer = new Signer(checkSignerCertificate: true);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/is not yet valid/');
        $signer->sign(
            'content',
            $credential['cert_der'],
            $credential['key'],
            [],
            new Config(Config::PROFILE_PADES_B_B),
            // The generated credential is valid from the moment it was made, so a
            // signing time well before that falls outside its validity period.
            self::SIGNING_TIME - (40 * 365 * 86_400),
        );
    }

    public function testPrepareRefusesACertificateThatCannotSignWhenAskedTo(): void
    {
        // The CA fixture carries keyUsage keyCertSign, cRLSign and nothing else.
        $signer = new Signer(checkSignerCertificate: true);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not admit signing/');
        $signer->prepare(
            \hash('sha256', 'content', true),
            Authority::ocsp()->certDer,
            new Config(Config::PROFILE_PADES_B_B),
            self::NOW,
        );
    }

    public function testBuildFromSignatureRefusesACertificateThatCannotSignWhenAskedTo(): void
    {
        // A request may be built by its own constructor and crosses a session or a
        // queue on the way here, so the certificate checks are applied at this point
        // as well as at prepare().
        $config = new Config(Config::PROFILE_PADES_B_B);
        $request = new SigningRequest(
            \hash('sha256', 'content', true),
            Authority::ocsp()->certDer,
            'sha256',
            self::NOW,
            false,
        );

        $signer = new Signer(checkSignerCertificate: true);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not admit signing/');
        $signer->buildFromSignature($request, 'signature', [], $config);
    }

    public function testBuildFromSignatureAcceptsAnyCertificateByDefault(): void
    {
        // Off by default, so a host that never opted in sees no refusal.
        $credential = $this->makeCredential();
        $config = new Config(Config::PROFILE_PADES_B_B);
        $signer = new Signer();

        $request = $signer->prepare(
            \hash('sha256', 'content', true),
            $credential['cert_der'],
            $config,
            self::SIGNING_TIME,
        );

        $signature = '';
        \openssl_sign($signer->signaturePayload($request), $signature, $credential['key'], OPENSSL_ALGO_SHA256);

        $this->assertNotSame('', $signer->buildFromSignature($request, $signature, [], $config));
    }

    public function testPrepareAcceptsAnyCertificateByDefault(): void
    {
        // Off by default, since a host may deliberately re-sign historical content.
        $request = (new Signer())->prepare(
            \hash('sha256', 'content', true),
            Authority::ocsp()->certDer,
            new Config(Config::PROFILE_PADES_B_B),
            self::SIGNING_TIME,
        );

        $this->assertSame(Authority::ocsp()->certDer, $request->signerCertDer);
    }

    /**
     * DER of the id-aa-signatureTimeStampToken OID, used as a presence probe.
     */
    private function timestampOidDer(): string
    {
        return $this->asn1->encodeObjectIdentifier(self::OID_SIGNATURE_TIMESTAMP);
    }

    /**
     * DER of the CMS signing-time OID, used as a presence probe.
     */
    private function signingTimeOidDer(): string
    {
        return $this->asn1->encodeObjectIdentifier(self::OID_SIGNING_TIME);
    }

    /**
     * A signed token whose certificate bag holds $count distinct members, on top
     * of the TSA's own certificate.
     */
    private function tokenWithCertificateBag(int $count): string
    {
        $bag = [];
        for ($i = 0; $i < $count; ++$i) {
            // Distinct members, so deduplication does not bring the count back down.
            $member = Authority::leaf()->certDer;
            $member[20] = \chr($i);
            $bag[] = $member;
        }

        return $this->der->signedTimestampToken($this->der->tstInfo('imprint', '2.16.840.1.101.3.4.2.1'), $bag);
    }

    /**
     * An RSA private key and a matching self-signed certificate.
     *
     * Memoised by the fixture, so the key is generated once per process rather
     * than once per test.
     *
     * @return array{key: OpenSSLAsymmetricKey, cert_pem: string, cert_der: string}
     */
    private function makeCredential(): array
    {
        $credential = Credentials::make();
        if ($credential === null) {
            $this->markTestSkipped('RSA key generation is not available');
        }

        return $credential;
    }
}
