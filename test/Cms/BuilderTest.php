<?php

declare(strict_types=1);

/**
 * BuilderTest.php
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

namespace Test\Cms;

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Builder;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Cms\Oid;
use Com\Tecnick\Pdf\Sign\Cms\SignatureEncoding;
use Com\Tecnick\Pdf\Sign\Cms\SignatureVerifier;
use Com\Tecnick\Pdf\Sign\Cms\SigningRequest;
use Com\Tecnick\Pdf\Sign\DigestAlgorithm;
use Com\Tecnick\Pdf\Sign\Exception;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Credentials;

/**
 * CMS Builder Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Builder::class)]
#[CoversClass(SignatureEncoding::class)]
final class BuilderTest extends TestCase
{
    private const SIGNING_TIME = 1_700_000_000;

    private Asn1 $asn1;

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
    }

    public function testSignRsaSha256ProducesVerifiableCms(): void
    {
        $cred = $this->makeCredential('rsa');
        $data = 'The quick brown fox jumps over the lazy dog.';

        $builder = new Builder($this->asn1);
        $cms = $builder->sign($data, $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME);

        $parts = $this->parseSignerInfo($cms);
        $this->assertSame(0xA0, $parts['signed_attrs']['tag']);
        $this->assertSame(0x04, $parts['signature']['tag']);
        $this->assertSame(0xA0, $parts['certificates']['tag']);
        $this->assertStringContainsString($cred['cert_der'], $parts['certificates']['value']);

        // Cryptographically verify the signature over the DER SET OF signed attributes.
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);

        // content-type present and equal to id-data.
        $contentType = $this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.3');
        $this->assertNotNull($contentType);
        $this->assertSame($this->asn1->encodeObjectIdentifier('1.2.840.113549.1.7.1'), $contentType['raw']);

        // signing-time is a UTCTime for a 2023 timestamp.
        $signingTime = $this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.5');
        $this->assertNotNull($signingTime);
        $this->assertSame(0x17, $signingTime['tag']);

        // message-digest equals SHA-256 of the content.
        $messageDigest = $this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.4');
        $this->assertNotNull($messageDigest);
        $this->assertSame(\hash('sha256', $data, true), $messageDigest['value']);

        // signing-certificate-v2 carries the SHA-256 hash of the signer certificate;
        // for SHA-256 the ESSCertIDv2 hashAlgorithm is omitted so certHash is first.
        $certHash = $this->firstCertHash('1.2.840.113549.1.9.16.2.47', $parts['signed_attrs']['value']);
        $this->assertSame(0x04, $certHash['tag']);
        $this->assertSame(\hash('sha256', $cred['cert_der'], true), $certHash['value']);
    }

    public function testSignOmitsSigningTimeForPadesBaseline(): void
    {
        $cred = $this->makeCredential('rsa');
        $data = 'PAdES-BASELINE forbids the CMS signing-time attribute.';

        $builder = new Builder($this->asn1);
        // includeSigningTime = false: the PAdES-BASELINE case, where the signing time
        // is carried by the /M signature dictionary entry rather than the CMS.
        $cms = $builder->sign($data, $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME, null, false);

        $parts = $this->parseSignerInfo($cms);
        // The signature still verifies over the (smaller) DER SET OF signed attributes.
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);

        // signing-time (1.2.840.113549.1.9.5) is absent.
        $this->assertNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.5'));

        // The other mandatory signed attributes remain present.
        $this->assertNotNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.3'));
        $this->assertNotNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.4'));
        $this->assertNotNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.16.2.47'));
    }

    public function testSignEcSha256ProducesVerifiableCms(): void
    {
        $cred = $this->makeCredential('ec');
        $data = 'elliptic-curve payload';

        $builder = new Builder($this->asn1);
        $cms = $builder->sign($data, $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME);

        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);
    }

    public function testSignRsaSha384IncludesEssCertHashAlgorithm(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);
        $cms = $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha384', self::SIGNING_TIME);

        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA384);

        // For a non-default digest, ESSCertIDv2 begins with the hashAlgorithm SEQUENCE.
        $scv2 = $this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.16.2.47');
        $this->assertNotNull($scv2);
        $certsOffset = 0;
        $certs = $this->asn1->readTlv($scv2['value'], $certsOffset);
        $essOffset = 0;
        $ess = $this->asn1->readTlv($certs['value'], $essOffset);
        $firstOffset = 0;
        $first = $this->asn1->readTlv($ess['value'], $firstOffset);
        $this->assertSame(0x30, $first['tag']);
    }

    public function testSignRsaSha512ProducesVerifiableCms(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);
        $cms = $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha512', self::SIGNING_TIME);

        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA512);
    }

    public function testSignEmbedsChainCertificates(): void
    {
        $cred = $this->makeCredential('rsa');
        $chainDer = $this->pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem'));

        $builder = new Builder($this->asn1);
        $cms = $builder->sign('data', $cred['cert_der'], $cred['key'], [$chainDer], 'sha256', self::SIGNING_TIME);

        $parts = $this->parseSignerInfo($cms);
        $this->assertStringContainsString($cred['cert_der'], $parts['certificates']['value']);
        $this->assertStringContainsString($chainDer, $parts['certificates']['value']);
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function signingTimeProvider(): array
    {
        return ['legacy profile' => [true], 'PAdES profile' => [false]];
    }

    #[DataProvider('signingTimeProvider')]
    public function testSignEmitsNoAttributeTypeOutsideTheReservedList(bool $includeSigningTime): void
    {
        // SigningRequest refuses a caller-supplied attribute of a type the builder
        // emits, RFC 5652 section 5.3 admitting each type once, so the reserved list
        // and the types this walk finds are pinned together.
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);
        $cms = $builder->sign(
            'data',
            $cred['cert_der'],
            $cred['key'],
            [],
            'sha256',
            self::SIGNING_TIME,
            null,
            $includeSigningTime,
        );

        $attributes = $this->parseSignerInfo($cms)['signed_attrs']['value'];

        $emitted = [];
        $offset = 0;
        while ($offset < \strlen($attributes)) {
            $attribute = $this->asn1->readTlv($attributes, $offset);
            $inner = 0;
            $type = $this->asn1->readTlv($attribute['value'], $inner);
            $emitted[] = $this->asn1->decodeObjectIdentifier($type['value']);
        }

        $this->assertNotSame([], $emitted);
        $this->assertSame([], \array_diff($emitted, Oid::BUILDER_ATTRIBUTES));
        $this->assertSame($includeSigningTime, \in_array(Oid::SIGNING_TIME, $emitted, true));
    }

    public function testSignWithoutTimestampHasNoUnsignedAttributes(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);
        $cms = $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME);

        $parts = $this->parseSignerInfo($cms);
        $this->assertNull($parts['unsigned_attrs']);
    }

    public function testSignEmbedsSignatureTimestampUnsignedAttribute(): void
    {
        $cred = $this->makeCredential('rsa');
        $token = $this->stubToken();

        $captured = '';
        $provider = static function (string $signature) use (&$captured, $token): string {
            $captured = $signature;
            return $token;
        };

        $builder = new Builder($this->asn1);
        $cms = $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME, $provider);

        $parts = $this->parseSignerInfo($cms);
        // The signature is cryptographically unchanged by the added unsigned attribute.
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);

        // The provider timestamps the raw SignerInfo signature bytes.
        $this->assertSame($parts['signature']['value'], $captured);

        // unsignedAttrs is a [1] IMPLICIT context tag carrying id-aa-signatureTimeStampToken.
        $this->assertNotNull($parts['unsigned_attrs']);
        $this->assertSame(0xA1, $parts['unsigned_attrs']['tag']);

        $tstValue = $this->attributeValue($parts['unsigned_attrs']['value'], '1.2.840.113549.1.9.16.2.14');
        $this->assertNotNull($tstValue);
        $this->assertSame($token, $tstValue['raw']);
    }

    public function testSignRejectsEmptySignatureTimestampToken(): void
    {
        $cred = $this->makeCredential('rsa');
        $provider = static fn(): string => '';

        $builder = new Builder($this->asn1);
        $this->expectException(Exception::class);
        $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME, $provider);
    }

    public function testSignRejectsASignatureTimestampTokenThatIsNotASignedData(): void
    {
        // certificateSet() parses every chain entry, and the timestamp attribute is
        // held to the same reading: the provider's value has to be a CMS SignedData
        // rather than merely a DER SEQUENCE.
        $cred = $this->makeCredential('rsa');
        $token = $this->asn1->encodeSequence($this->asn1->encodeOctetString('<html>502 Bad Gateway</html>'));

        $builder = new Builder($this->asn1);
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/signature timestamp token is not a CMS SignedData/');
        $builder->sign(
            'data',
            $cred['cert_der'],
            $cred['key'],
            [],
            'sha256',
            self::SIGNING_TIME,
            static fn(): string => $token,
        );
    }

    public function testSignUsesGeneralizedTimeForFarFuture(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);
        // 2100-01-01T00:00:00Z is outside the UTCTime range (1950-2049).
        $cms = $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha256', 4_102_444_800);

        $parts = $this->parseSignerInfo($cms);
        $signingTime = $this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.5');
        $this->assertNotNull($signingTime);
        $this->assertSame(0x18, $signingTime['tag']);
    }

    public function testSignRejectsUnsupportedDigest(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);
        $this->expectException(Exception::class);
        $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'md5', self::SIGNING_TIME);
    }

    public function testSignFailsWithNonSigningKey(): void
    {
        $cred = $this->makeCredential('rsa');
        $publicKey = \openssl_pkey_get_public($cred['cert_pem']);
        if ($publicKey === false) {
            $this->fail('Unable to load public key');
        }

        $builder = new Builder($this->asn1);
        $this->expectException(Exception::class);
        \set_error_handler(static fn(): bool => true);
        try {
            $builder->sign('data', $cred['cert_der'], $publicKey, [], 'sha256', self::SIGNING_TIME);
        } finally {
            \restore_error_handler();
        }
    }

    public function testSignRejectsUnsupportedKeyType(): void
    {
        $cred = $this->makeCredential('dsa');
        $builder = new Builder($this->asn1);
        $this->expectException(Exception::class);
        $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME);
    }

    public function testSignRejectsAKeyThatDoesNotMatchTheCertificate(): void
    {
        $signer = $this->makeCredential('rsa');
        $other = $this->otherCredential();

        $builder = new Builder($this->asn1);
        $this->expectException(Exception::class);
        // The CMS would carry a signature the embedded certificate cannot verify.
        $builder->sign('data', $signer['cert_der'], $other['key'], [], 'sha256', self::SIGNING_TIME);
    }

    public function testDataToBeSignedIsWhatSignSigns(): void
    {
        $cred = $this->makeCredential('rsa');
        $data = 'two-phase payload';

        $builder = new Builder($this->asn1);
        $cms = $builder->sign($data, $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME);
        $parts = $this->parseSignerInfo($cms);

        $request = $this->makeRequest($cred['cert_der'], $data);
        $signaturePayload = $builder->signaturePayload($request);

        // The SignerInfo carries the same attributes under [0] IMPLICIT; only the tag differs.
        $this->assertSame($this->asn1->encodeSet($parts['signed_attrs']['value']), $signaturePayload);
        $this->assertSame(0x31, \ord($signaturePayload[0]));

        $publicKey = \openssl_pkey_get_public($cred['cert_pem']);
        $this->assertNotFalse($publicKey);
        $this->assertSame(1, \openssl_verify(
            $signaturePayload,
            $parts['signature']['value'],
            $publicKey,
            OPENSSL_ALGO_SHA256,
        ));
    }

    public function testAssembleReproducesWhatSignProduces(): void
    {
        $cred = $this->makeCredential('rsa');
        $data = 'two-phase payload';

        $builder = new Builder($this->asn1);
        $signed = $builder->sign($data, $cred['cert_der'], $cred['key'], [], 'sha256', self::SIGNING_TIME);

        $request = $this->makeRequest($cred['cert_der'], $data);
        $signature = '';
        $this->assertTrue(\openssl_sign(
            $builder->signaturePayload($request),
            $signature,
            $cred['key'],
            OPENSSL_ALGO_SHA256,
        ));
        $built = $builder->buildFromSignature($request, $signature, []);

        // RSA PKCS#1 v1.5 is deterministic, so the two paths agree byte for byte.
        $this->assertSame($signed, $built);
    }

    public function testAssembleFromAStreamedDigestWithoutTheContent(): void
    {
        $cred = $this->makeCredential('rsa');
        $stream = \fopen('php://temp', 'r+');
        $this->assertNotFalse($stream);
        \fwrite($stream, 'a document read in chunks');
        \rewind($stream);

        // The digest comes from the stream; the content is never held as a string.
        $context = \hash_init('sha256');
        \hash_update_stream($context, $stream);
        \fclose($stream);

        $request = new SigningRequest(\hash_final($context, true), $cred['cert_der'], 'sha256', self::SIGNING_TIME);

        $builder = new Builder($this->asn1);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);
        $cms = $builder->buildFromSignature($request, $signature, []);

        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);

        $messageDigest = $this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.4');
        $this->assertNotNull($messageDigest);
        $this->assertSame(\hash('sha256', 'a document read in chunks', true), $messageDigest['value']);
    }

    public function testAssembleRejectsAnEmptySignature(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($this->makeRequest($cred['cert_der']), '', []);
    }

    public function testAssembleRejectsASignatureOverDifferentBytes(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $signature = '';
        \openssl_sign('some other bytes', $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($this->makeRequest($cred['cert_der']), $signature, []);
    }

    public function testAssembleLeavesNoOpenSslErrorsBehindOnARefusedSignature(): void
    {
        // A refused signature is reported as an Exception, so the OpenSSL queue
        // entries are discarded rather than left for the host.
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        // Drain whatever the credential generation left behind.
        Certificate::clearOpenSslErrors();

        try {
            $builder->buildFromSignature($this->makeRequest($cred['cert_der']), \str_repeat("\x01", 256), []);
            $this->fail('the signature should have been refused');
        } catch (Exception) {
            $this->assertFalse(\openssl_error_string());
        }
    }

    public function testAssembleRejectsASignatureFromAnotherKey(): void
    {
        $signer = $this->makeCredential('rsa');
        $other = $this->otherCredential();
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($signer['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $other['key'], OPENSSL_ALGO_SHA256);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($request, $signature, []);
    }

    public function testAssembleRejectsASignatureForAStaleRequest(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $signed = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($signed), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        // The signing time differs between the two calls, so the attributes differ.
        $drifted = new SigningRequest($signed->messageDigest, $signed->signerCertDer, 'sha256', self::SIGNING_TIME + 1);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($drifted, $signature, []);
    }

    public function testAssembleAcceptsAP1363EcdsaSignature(): void
    {
        $cred = $this->makeCredential('ec');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $cms = $builder->buildFromSignature(
            $request,
            $this->derEcdsaToP1363($signature, 32),
            [],
            null,
            SignatureEncoding::P1363,
        );

        // The CMS carries the DER form regardless of how the signer returned it.
        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);
        $this->assertSame($signature, $parts['signature']['value']);
    }

    public function testAssembleRejectsAP1363SignatureDeclaredAsDer(): void
    {
        $cred = $this->makeCredential('ec');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($request, $this->derEcdsaToP1363($signature, 32), [], null, 'der');
    }

    public function testAssembleRejectsAnOddLengthP1363Signature(): void
    {
        $cred = $this->makeCredential('ec');
        $builder = new Builder($this->asn1);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($this->makeRequest($cred['cert_der']), \str_repeat("\x01", 63), [], null, 'p1363');
    }

    public function testAssembleRejectsAnUnknownSignatureEncoding(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($this->makeRequest($cred['cert_der']), 'signature', [], null, 'raw');
    }

    public function testAssembleRejectsAnUnsupportedCertificateKeyType(): void
    {
        $cred = $this->makeCredential('dsa');
        $builder = new Builder($this->asn1);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($this->makeRequest($cred['cert_der']), 'signature', []);
    }

    public function testAssembleEmbedsAnExtraSignedAttribute(): void
    {
        $cred = $this->makeCredential('rsa');
        $policy = $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier('2.16.76.1.7.1.1.2.3'));

        $request = new SigningRequest(
            \hash('sha256', 'data', true),
            $cred['cert_der'],
            'sha256',
            self::SIGNING_TIME,
            true,
            ['1.2.840.113549.1.9.16.2.15' => $policy],
        );

        $builder = new Builder($this->asn1);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);
        $cms = $builder->buildFromSignature($request, $signature, []);

        $parts = $this->parseSignerInfo($cms);
        // The extra attribute is inside the SET the signature covers.
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);

        $embedded = $this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.16.2.15');
        $this->assertNotNull($embedded);
        $this->assertSame($policy, $embedded['raw']);

        // The mandatory attributes are untouched.
        $this->assertNotNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.3'));
        $this->assertNotNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.4'));
        $this->assertNotNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.16.2.47'));
    }

    public function testAssembleEmbedsChainCertificates(): void
    {
        $cred = $this->makeCredential('rsa');
        $chainDer = $this->pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem'));

        $builder = new Builder($this->asn1);
        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);
        $cms = $builder->buildFromSignature($request, $signature, [$chainDer]);

        $parts = $this->parseSignerInfo($cms);
        $this->assertStringContainsString($cred['cert_der'], $parts['certificates']['value']);
        $this->assertStringContainsString($chainDer, $parts['certificates']['value']);
    }

    public function testAssembleTimestampsAnExternallyProducedSignature(): void
    {
        $cred = $this->makeCredential('rsa');
        $token = $this->stubToken();

        $captured = '';
        $provider = static function (string $signature) use (&$captured, $token): string {
            $captured = $signature;
            return $token;
        };

        $builder = new Builder($this->asn1);
        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);
        $cms = $builder->buildFromSignature($request, $signature, [], $provider);

        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);
        $this->assertSame($signature, $captured);

        $tstValue = $this->attributeValue($parts['unsigned_attrs']['value'] ?? '', '1.2.840.113549.1.9.16.2.14');
        $this->assertNotNull($tstValue);
        $this->assertSame($token, $tstValue['raw']);
    }

    public function testAssembleOmitsSigningTimeWhenTheRequestDoes(): void
    {
        $cred = $this->makeCredential('rsa');

        $request = new SigningRequest(
            \hash('sha256', 'data', true),
            $cred['cert_der'],
            'sha256',
            self::SIGNING_TIME,
            false,
        );

        $builder = new Builder($this->asn1);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);
        $cms = $builder->buildFromSignature($request, $signature, []);

        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], OPENSSL_ALGO_SHA256);
        $this->assertNull($this->attributeValue($parts['signed_attrs']['value'], '1.2.840.113549.1.9.5'));
    }

    /**
     * Build the default two-phase request used by the buildFromSignature tests.
     */
    /**
     * A structurally minimal RFC 3161 token: a CMS SignedData ContentInfo.
     *
     * Builder holds the value a provider returns to that reading before embedding
     * it. Nothing here is signed; what is under test is that the token reaches
     * unsignedAttrs unchanged.
     */
    /**
     * Tokens that are a ContentInfo carrying a SignedData and not much else.
     *
     * @return array<string, array{callable(Asn1): string}>
     */
    public static function looselyShapedTokenProvider(): array
    {
        $signedData = static fn(Asn1 $asn1, string $body): string => $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier(Oid::SIGNED_DATA) . $asn1->encodeContext(0, $asn1->encodeSequence($body)),
        );

        $head = static fn(Asn1 $asn1): string => (
            $asn1->encodeInteger(3)
            . $asn1->encodeSet('')
            . $asn1->encodeSequence($asn1->encodeObjectIdentifier(Oid::TST_INFO))
        );

        return [
            'version is an OCTET STRING' => [
                static fn(Asn1 $asn1): string => $signedData(
                    $asn1,
                    $asn1->encodeOctetString("\x03")
                        . $asn1->encodeSet('')
                        . $asn1->encodeSequence($asn1->encodeObjectIdentifier(Oid::TST_INFO))
                        . $asn1->encodeSet($asn1->encodeSequence($asn1->encodeInteger(1))),
                ),
            ],
            'digestAlgorithms holds chosen bytes' => [
                static fn(Asn1 $asn1): string => $signedData(
                    $asn1,
                    $asn1->encodeInteger(3)
                        . $asn1->encodeOctetString(\str_repeat('P', 64))
                        . $asn1->encodeSequence($asn1->encodeObjectIdentifier(Oid::TST_INFO))
                        . $asn1->encodeSet($asn1->encodeSequence($asn1->encodeInteger(1))),
                ),
            ],
            'the CertificateSet holds a non-certificate' => [
                static fn(Asn1 $asn1): string => $signedData(
                    $asn1,
                    $head($asn1) . $asn1->encodeContext(0, $asn1->encodeSequence($asn1->encodeInteger(1)))
                        . $asn1->encodeSet($asn1->encodeSequence($asn1->encodeInteger(1))),
                ),
            ],
            'the crls field holds something else' => [
                static fn(Asn1 $asn1): string => $signedData(
                    $asn1,
                    $head($asn1) . $asn1->encodeContext(1, $asn1->encodeOctetString('x'))
                        . $asn1->encodeSet($asn1->encodeSequence($asn1->encodeInteger(1))),
                ),
            ],
            'no SignerInfo at all' => [
                static fn(Asn1 $asn1): string => $signedData($asn1, $head($asn1) . $asn1->encodeSet('')),
            ],
            'bytes after the signerInfos' => [
                static fn(Asn1 $asn1): string => $signedData(
                    $asn1,
                    $head($asn1) . $asn1->encodeSet($asn1->encodeSequence($asn1->encodeInteger(1)))
                        . $asn1->encodeOctetString(\str_repeat('P', 64)),
                ),
            ],
        ];
    }

    /**
     * @param callable(Asn1): string $build
     */
    #[DataProvider('looselyShapedTokenProvider')]
    public function testBuildFromSignatureHoldsTheTimestampTokenToTheStrictRead(callable $build): void
    {
        // The token is embedded verbatim, so it gets the strict reading
        // Timestamp\Client applies before returning one. OpenSSL decodes none of
        // these.
        $cred = $this->makeCredential('rsa');
        $token = $build($this->asn1);

        $builder = new Builder($this->asn1);
        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/is not a CMS SignedData/');
        $builder->buildFromSignature($request, $signature, [], static fn(string $_bytes): string => $token);
    }

    private function stubToken(): string
    {
        // The SignerInfo is a skeleton, but there is one: a SignedData carrying none
        // is not a timestamp token.
        $signedData = $this->asn1->encodeSequence(
            $this->asn1->encodeInteger(3)
                . $this->asn1->encodeSet('')
                . $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier(Oid::TST_INFO))
                . $this->asn1->encodeSet($this->asn1->encodeSequence($this->asn1->encodeInteger(1))),
        );

        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier(Oid::SIGNED_DATA) . $this->asn1->encodeContext(0, $signedData),
        );
    }

    private function makeRequest(string $certDer, string $data = 'data'): SigningRequest
    {
        return new SigningRequest(\hash('sha256', $data, true), $certDer, 'sha256', self::SIGNING_TIME);
    }

    /**
     * Convert a DER ECDSA signature to the fixed-width r || s form some tokens return.
     *
     * @param int $fieldSize Byte length of the curve order.
     */
    private function derEcdsaToP1363(string $der, int $fieldSize): string
    {
        $offset = 0;
        $sequence = $this->asn1->readTlv($der, $offset);
        $inner = 0;
        $r = $this->asn1->readTlv($sequence['value'], $inner);
        $s = $this->asn1->readTlv($sequence['value'], $inner);

        return $this->fixedWidth($r['value'], $fieldSize) . $this->fixedWidth($s['value'], $fieldSize);
    }

    /**
     * Left-pad a DER INTEGER magnitude to the curve field width.
     */
    private function fixedWidth(string $magnitude, int $fieldSize): string
    {
        $trimmed = \ltrim($magnitude, "\x00");
        return \str_pad($trimmed, $fieldSize, "\x00", STR_PAD_LEFT);
    }

    public function testAssembleRejectsATimestampProviderThatReturnsANonString(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        // PHP does not check a callable's return type at the call boundary, so a
        // provider returning a non-string is rejected rather than concatenated into
        // the SignerInfo.
        $this->expectException(Exception::class);
        // @mago-expect analysis:invalid-argument
        $builder->buildFromSignature($request, $signature, [], static fn(string $_bytes): int => 1);
    }

    public function testAssembleRejectsAnEmptyChainEntry(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $this->expectException(Exception::class);
        $builder->buildFromSignature($request, $signature, ['']);
    }

    /**
     * @return array<string, array{string, int<1, max>, int}>
     */
    public static function ecdsaCurveProvider(): array
    {
        return [
            // [curve, half-width in bytes, openssl digest]
            'P-256' => ['prime256v1', 32, OPENSSL_ALGO_SHA256],
            'P-384' => ['secp384r1', 48, OPENSSL_ALGO_SHA384],
            'P-521' => ['secp521r1', 66, OPENSSL_ALGO_SHA512],
        ];
    }

    /**
     * @param int<1, max> $half
     */
    #[DataProvider('ecdsaCurveProvider')]
    public function testAssembleAcceptsP1363AcrossCurves(string $curve, int $half, int $opensslAlgo): void
    {
        // P-521 halves are 66 bytes, so the conversion must not assume a power of two.
        $digest = match ($opensslAlgo) {
            OPENSSL_ALGO_SHA384 => 'sha384',
            OPENSSL_ALGO_SHA512 => 'sha512',
            default => 'sha256',
        };

        $cred = $this->makeCredential('ec', $curve);
        $builder = new Builder($this->asn1);

        $request = new SigningRequest(\hash($digest, 'content', true), $cred['cert_der'], $digest, self::SIGNING_TIME);

        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], $opensslAlgo);

        $cms = $builder->buildFromSignature(
            $request,
            $this->derEcdsaToP1363($signature, $half),
            [],
            null,
            SignatureEncoding::P1363,
        );

        $parts = $this->parseSignerInfo($cms);
        $this->assertVerifies($parts, $cred['cert_pem'], $opensslAlgo);
        $this->assertSame($signature, $parts['signature']['value']);
    }

    public function testSignedAttributesAreSortedByEncoding(): void
    {
        // X.690 section 11.6: SET OF members are ordered by their encodings. An
        // extra attribute whose OID sorts before content-type has to come first.
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        // 1.2.3.4 encodes as 06 03 2a 03 04, which sorts before content-type's
        // 06 09 2a 86 48 86 f7 0d 01 09 03.
        $request = new SigningRequest(
            \hash('sha256', 'content', true),
            $cred['cert_der'],
            'sha256',
            self::SIGNING_TIME,
            false,
            ['1.2.3.4' => $this->asn1->encodeOctetString('policy')],
        );

        $attrs = $builder->signaturePayload($request);
        $offset = 0;
        $set = $this->asn1->readTlv($attrs, $offset);
        $this->assertSame(0x31, $set['tag']);

        $encoded = [];
        $inner = 0;
        while ($inner < \strlen($set['value'])) {
            $encoded[] = $this->asn1->readTlv($set['value'], $inner)['raw'];
        }

        $sorted = $encoded;
        \usort($sorted, static function (string $one, string $two): int {
            $length = \max(\strlen($one), \strlen($two));
            return \strcmp(\str_pad($one, $length, "\x00"), \str_pad($two, $length, "\x00"));
        });

        $this->assertSame($sorted, $encoded, 'signed attributes are not in DER SET OF order');
        $this->assertCount(4, $encoded);
    }

    public function testCertificateSetDeduplicatesTheSignerCertificate(): void
    {
        // A chain that already carries the leaf, which is the shape
        // openssl_pkcs12_read() and a PEM bundle both hand over, is deduplicated
        // against the signer certificate.
        $cred = $this->makeCredential('rsa');

        $builder = new Builder($this->asn1);
        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $cms = $builder->buildFromSignature($request, $signature, [$cred['cert_der']]);
        $parts = $this->parseSignerInfo($cms);

        $encoded = [];
        $inner = 0;
        while ($inner < \strlen($parts['certificates']['value'])) {
            $encoded[] = $this->asn1->readTlv($parts['certificates']['value'], $inner)['raw'];
        }

        $this->assertSame([$cred['cert_der']], $encoded);
        $this->assertSame(1, \substr_count($cms, $cred['cert_der']));
    }

    public function testSignAcceptsEveryDigestAlgorithmTheEnumDeclares(): void
    {
        // DigestAlgorithm is the closed set for both the CMS builder and the RFC 3161
        // message imprint, and Builder keeps its own table, so the two are pinned
        // together.
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        foreach (DigestAlgorithm::cases() as $case) {
            $cms = $builder->sign('data', $cred['cert_der'], $cred['key'], [], $case->value, 1_700_000_000);
            $this->assertNotSame('', $cms);
        }
    }

    public function testSignAcceptsTheEnumCaseAsWellAsItsName(): void
    {
        // Config, Timestamp\Config and SigningRequest all take string|DigestAlgorithm,
        // as Builder does.
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $this->assertSame(
            $builder->sign('data', $cred['cert_der'], $cred['key'], [], 'sha384', 1_700_000_000),
            $builder->sign('data', $cred['cert_der'], $cred['key'], [], DigestAlgorithm::Sha384, 1_700_000_000),
        );
    }

    public function testSignIdentifiesAnRsaSignatureWithRsaEncryption(): void
    {
        // RFC 3370 section 3.2: rsaEncryption with NULL parameters is the PKCS #1
        // v1.5 signature value identifier in CMS, whatever the digest. The OID is
        // SignatureVerifier's, so the emitting and the reading halves share it.
        $cred = $this->makeCredential('rsa');
        $cms = (new Builder($this->asn1))->sign('data', $cred['cert_der'], $cred['key'], [], 'sha512', 1_700_000_000);

        $this->assertSame(
            $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier(SignatureVerifier::OID_RSA_ENCRYPTION) . $this->asn1->encodeNull(),
            ),
            $this->parseSignerInfo($cms)['signature_algorithm']['raw'],
        );
    }

    public function testCertificateSetIsSortedByEncoding(): void
    {
        $cred = $this->makeCredential('rsa');
        $other = $this->otherCredential();

        $builder = new Builder($this->asn1);
        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $cms = $builder->buildFromSignature($request, $signature, [$other['cert_der']]);
        $parts = $this->parseSignerInfo($cms);

        $encoded = [];
        $inner = 0;
        while ($inner < \strlen($parts['certificates']['value'])) {
            $encoded[] = $this->asn1->readTlv($parts['certificates']['value'], $inner)['raw'];
        }

        $this->assertCount(2, $encoded);

        // CertificateSet is a SET OF (RFC 5652 section 10.2.3), so DER order applies.
        $sorted = $encoded;
        \usort($sorted, static function (string $one, string $two): int {
            $length = \max(\strlen($one), \strlen($two));
            return \strcmp(\str_pad($one, $length, "\x00"), \str_pad($two, $length, "\x00"));
        });

        $this->assertSame($sorted, $encoded, 'CertificateSet is not in DER SET OF order');
    }

    public function testAssembleAcceptsAChainEntryGivenAsPem(): void
    {
        // Either encoding is accepted for a chain entry.
        $cred = $this->makeCredential('rsa');
        $chainDer = $this->pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem'));
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $fromPem = $builder->buildFromSignature($request, $signature, [Certificate::derToPem($chainDer)]);
        $fromDer = $builder->buildFromSignature($request, $signature, [$chainDer]);

        $this->assertSame($fromDer, $fromPem);
    }

    public function testAssembleRejectsAChainEntryThatIsNotACertificate(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        // A DER SEQUENCE that is not a certificate, so every entry is parsed rather
        // than tag-checked.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid chain certificate 0/');
        $builder->buildFromSignature(
            $request,
            $signature,
            [$this->asn1->encodeSequence($this->asn1->encodeOctetString(\str_repeat('x', 200)))],
        );
    }

    public function testAssembleRejectsAChainEntryThatIsNotAString(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        // Typed loosely on purpose: an entry that is not a string would reach
        // Certificate::toDer() as a TypeError rather than an Exception.
        /** @var list<string> $chain */
        $chain = [42];

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid chain certificate 0/');
        $builder->buildFromSignature($request, $signature, $chain);
    }

    public function testAssembleRejectsATimestampTokenThatIsNotDer(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        // An HTTP error body where a token was expected.
        $this->expectException(Exception::class);
        $builder->buildFromSignature(
            $request,
            $signature,
            [],
            static fn(string $_bytes): string => '<html>502 Bad Gateway</html>',
        );
    }

    public function testAssembleRejectsATrailedTimestampToken(): void
    {
        $cred = $this->makeCredential('rsa');
        $builder = new Builder($this->asn1);

        $request = $this->makeRequest($cred['cert_der']);
        $signature = '';
        \openssl_sign($builder->signaturePayload($request), $signature, $cred['key'], OPENSSL_ALGO_SHA256);

        $trailed = $this->asn1->encodeSequence($this->asn1->encodeInteger(1)) . 'trailing';

        $this->expectException(Exception::class);
        $builder->buildFromSignature($request, $signature, [], static fn(string $_bytes): string => $trailed);
    }

    /**
     * A second RSA credential, distinct from the one makeCredential() returns.
     *
     * @return array{key: OpenSSLAsymmetricKey, cert_pem: string, cert_der: string}
     */
    private function otherCredential(): array
    {
        $cred = Credentials::make('rsa', 'prime256v1', 'tc-lib-pdf-sign other');
        if ($cred === null) {
            $this->markTestSkipped('RSA key generation is not available');
        }

        return $cred;
    }

    /**
     * @return array{key: OpenSSLAsymmetricKey, cert_pem: string, cert_der: string}
     */
    private function makeCredential(string $keyType, string $curve = 'prime256v1'): array
    {
        $cred = Credentials::make($keyType, $curve);
        if ($cred === null) {
            $this->markTestSkipped($keyType . ' (' . $curve . ') key generation is not available');
        }

        return $cred;
    }

    private function pemToDer(string $pem): string
    {
        $stripped = (string) \preg_replace('/-----[^-]+-----|\s+/', '', $pem);
        $der = \base64_decode($stripped, true);
        if ($der === false) {
            $this->fail('Invalid PEM');
        }

        return $der;
    }

    /**
     * Verify the SignerInfo signature over the reconstructed DER SET OF signed attributes.
     *
     * @param array{signed_attrs: array{tag:int,value:string,raw:string}, signature: array{tag:int,value:string,raw:string}, certificates: array{tag:int,value:string,raw:string}, unsigned_attrs: array{tag:int,value:string,raw:string}|null, signature_algorithm: array{tag:int,value:string,raw:string}} $parts
     */
    private function assertVerifies(array $parts, string $certPem, int $opensslAlgo): void
    {
        $publicKey = \openssl_pkey_get_public($certPem);
        if ($publicKey === false) {
            $this->fail('Unable to load public key');
        }

        $signedAttrsSet = $this->asn1->encodeSet($parts['signed_attrs']['value']);
        $result = \openssl_verify($signedAttrsSet, $parts['signature']['value'], $publicKey, $opensslAlgo);
        $this->assertSame(1, $result);
    }

    /**
     * Descend into a SigningCertificate attribute and return the ESSCertID certHash TLV.
     *
     * @return array{tag: int, value: string, raw: string}
     */
    private function firstCertHash(string $oid, string $attrsDer): array
    {
        $value = $this->attributeValue($attrsDer, $oid);
        $this->assertNotNull($value);
        $certsOffset = 0;
        $certs = $this->asn1->readTlv($value['value'], $certsOffset);
        $essOffset = 0;
        $ess = $this->asn1->readTlv($certs['value'], $essOffset);
        $hashOffset = 0;
        return $this->asn1->readTlv($ess['value'], $hashOffset);
    }

    /**
     * Find an Attribute by OID and return the first value TLV of its value SET.
     *
     * @return array{tag: int, value: string, raw: string}|null
     */
    private function attributeValue(string $attrsDer, string $oid): ?array
    {
        $oidDer = $this->asn1->encodeObjectIdentifier($oid);
        $offset = 0;
        $length = \strlen($attrsDer);
        while ($offset < $length) {
            $attribute = $this->asn1->readTlv($attrsDer, $offset);
            $inner = 0;
            $attrOid = $this->asn1->readTlv($attribute['value'], $inner);
            if ($attrOid['raw'] === $oidDer) {
                $set = $this->asn1->readTlv($attribute['value'], $inner);
                $valueOffset = 0;
                return $this->asn1->readTlv($set['value'], $valueOffset);
            }
        }

        return null;
    }

    /**
     * Navigate a CMS ContentInfo to the SignerInfo fields under test.
     *
     * @return array{signed_attrs: array{tag:int,value:string,raw:string}, signature: array{tag:int,value:string,raw:string}, certificates: array{tag:int,value:string,raw:string}, unsigned_attrs: array{tag:int,value:string,raw:string}|null, signature_algorithm: array{tag:int,value:string,raw:string}}
     */
    private function parseSignerInfo(string $cms): array
    {
        $offset = 0;
        $contentInfo = $this->asn1->readTlv($cms, $offset);

        $ciOffset = 0;
        $this->asn1->readTlv($contentInfo['value'], $ciOffset); // contentType OID
        $explicit = $this->asn1->readTlv($contentInfo['value'], $ciOffset); // [0] EXPLICIT

        $sdOffset = 0;
        $signedData = $this->asn1->readTlv($explicit['value'], $sdOffset);

        $sdInner = 0;
        $this->asn1->readTlv($signedData['value'], $sdInner); // version
        $this->asn1->readTlv($signedData['value'], $sdInner); // digestAlgorithms
        $this->asn1->readTlv($signedData['value'], $sdInner); // encapContentInfo
        $certificates = $this->asn1->readTlv($signedData['value'], $sdInner); // certificates [0]
        $signerInfos = $this->asn1->readTlv($signedData['value'], $sdInner); // signerInfos SET

        $siOffset = 0;
        $signerInfo = $this->asn1->readTlv($signerInfos['value'], $siOffset);

        $siInner = 0;
        $this->asn1->readTlv($signerInfo['value'], $siInner); // version
        $this->asn1->readTlv($signerInfo['value'], $siInner); // sid
        $this->asn1->readTlv($signerInfo['value'], $siInner); // digestAlgorithm
        $signedAttrs = $this->asn1->readTlv($signerInfo['value'], $siInner); // [0] IMPLICIT
        $signatureAlgorithm = $this->asn1->readTlv($signerInfo['value'], $siInner);
        $signature = $this->asn1->readTlv($signerInfo['value'], $siInner); // signature

        $unsignedAttrs = null;
        if ($siInner < \strlen($signerInfo['value'])) {
            $unsignedAttrs = $this->asn1->readTlv($signerInfo['value'], $siInner); // [1] IMPLICIT
        }

        return [
            'signed_attrs' => $signedAttrs,
            'signature' => $signature,
            'signature_algorithm' => $signatureAlgorithm,
            'certificates' => $certificates,
            'unsigned_attrs' => $unsignedAttrs,
        ];
    }
}
