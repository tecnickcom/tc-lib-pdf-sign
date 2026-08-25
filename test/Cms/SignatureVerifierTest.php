<?php

declare(strict_types=1);

/**
 * SignatureVerifierTest.php
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
use Com\Tecnick\Pdf\Sign\Cms\SignatureVerifier;
use Com\Tecnick\Pdf\Sign\Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;

/**
 * CMS SignatureVerifier Test
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(SignatureVerifier::class)]
final class SignatureVerifierTest extends TestCase
{
    private Asn1 $asn1;

    private SignatureVerifier $verifier;

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->verifier = new SignatureVerifier($this->asn1);
    }

    public function testVerifyAcceptsAGenuineSignature(): void
    {
        $authority = Authority::ocsp();
        $signed = $this->asn1->encodeSequence($this->asn1->encodeInteger(42));

        $this->verifier->verify(
            $signed,
            $this->algorithmIdentifier(Authority::SIGNATURE_OID),
            $authority->sign($signed),
            $authority->certDer,
        );

        $this->expectNotToPerformAssertions();
    }

    public function testVerifyAcceptsRsaEncryptionWithTheDigestTheCallerRead(): void
    {
        // RFC 3370 section 3.2: rsaEncryption identifies a PKCS #1 v1.5 signature
        // value whatever the digest, which the structure carries in a field of its
        // own. It is what Cms\Builder emits for an RSA signer.
        $authority = Authority::ocsp();
        $signed = $this->asn1->encodeSequence($this->asn1->encodeInteger(42));

        $this->verifier->verify(
            $signed,
            $this->algorithmIdentifier(SignatureVerifier::OID_RSA_ENCRYPTION),
            $authority->sign($signed),
            $authority->certDer,
            'sha256',
        );

        $this->expectNotToPerformAssertions();
    }

    public function testVerifyRejectsRsaEncryptionWithTheWrongDigest(): void
    {
        $authority = Authority::ocsp();
        $signed = $this->asn1->encodeSequence($this->asn1->encodeInteger(42));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not verify/');
        $this->verifier->verify(
            $signed,
            $this->algorithmIdentifier(SignatureVerifier::OID_RSA_ENCRYPTION),
            $authority->sign($signed),
            $authority->certDer,
            'sha512',
        );
    }

    public function testVerifyRejectsRsaEncryptionWithNoDigestSupplied(): void
    {
        // The identifier names no digest, so the caller supplies the one the
        // structure declared.
        $authority = Authority::ocsp();
        $signed = $this->asn1->encodeSequence($this->asn1->encodeInteger(42));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/names no digest/');
        $this->verifier->verify(
            $signed,
            $this->algorithmIdentifier(SignatureVerifier::OID_RSA_ENCRYPTION),
            $authority->sign($signed),
            $authority->certDer,
        );
    }

    public function testVerifyRejectsAnUnsupportedSuppliedDigest(): void
    {
        $authority = Authority::ocsp();
        $signed = $this->asn1->encodeSequence($this->asn1->encodeInteger(42));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported digest algorithm: md5/');
        $this->verifier->verify(
            $signed,
            $this->algorithmIdentifier(SignatureVerifier::OID_RSA_ENCRYPTION),
            $authority->sign($signed),
            $authority->certDer,
            'md5',
        );
    }

    public function testVerifyHoldsASuppliedSha1ToTheSameOptIn(): void
    {
        // rsaEncryption is not the way round the bar the rest of the class sets.
        $authority = Authority::ocsp();
        $signed = $this->asn1->encodeSequence($this->asn1->encodeInteger(42));
        $identifier = $this->algorithmIdentifier(SignatureVerifier::OID_RSA_ENCRYPTION);

        $signature = $authority->sign($signed, OPENSSL_ALGO_SHA1);

        try {
            $this->verifier->verify($signed, $identifier, $signature, $authority->certDer, 'sha1');
            $this->fail('SHA-1 should have been refused');
        } catch (Exception $e) {
            $this->assertMatchesRegularExpression('/Refusing the SHA-1 digest algorithm/', $e->getMessage());
        }

        (new SignatureVerifier($this->asn1, true))->verify(
            $signed,
            $identifier,
            $signature,
            $authority->certDer,
            'sha1',
        );
    }

    public function testVerifyRejectsAnAlgorithmThatDoesNotMatchTheKeyType(): void
    {
        // openssl_verify() reads the algorithm from the key and takes only the digest
        // from the OID, so without this an RSA signature labelled ecdsa-with-SHA256
        // would verify against an RSA certificate.
        $authority = Authority::ocsp();
        $signed = $this->asn1->encodeSequence($this->asn1->encodeInteger(42));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not match the certificate key/');
        $this->verifier->verify(
            $signed,
            $this->algorithmIdentifier('1.2.840.10045.4.3.2'),
            $authority->sign($signed),
            $authority->certDer,
        );
    }

    public function testVerifyLeavesNoOpenSslErrorsBehind(): void
    {
        // The queue is process-wide and never drained by PHP, so its entries are
        // discarded rather than left for the host.
        Certificate::clearOpenSslErrors();
        $authority = Authority::ocsp();

        try {
            $this->verifier->verify(
                $this->asn1->encodeSequence($this->asn1->encodeInteger(42)),
                $this->algorithmIdentifier(Authority::SIGNATURE_OID),
                'not a signature',
                $authority->certDer,
            );
            $this->fail('Expected the signature to be refused');
        } catch (Exception) {
            $this->assertFalse(\openssl_error_string());
        }
    }

    public function testVerifyRejectsASignatureOverOtherBytes(): void
    {
        $authority = Authority::ocsp();

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not verify/');
        $this->verifier->verify(
            'the bytes that were signed',
            $this->algorithmIdentifier(Authority::SIGNATURE_OID),
            $authority->sign('other bytes'),
            $authority->certDer,
        );
    }

    public function testVerifyRejectsAnotherKey(): void
    {
        $signed = 'payload';

        $this->expectException(Exception::class);
        $this->verifier->verify(
            $signed,
            $this->algorithmIdentifier(Authority::SIGNATURE_OID),
            Authority::ltv()->sign($signed),
            Authority::ocsp()->certDer,
        );
    }

    public function testVerifyRejectsAnUnreadableCertificate(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unreadable signing certificate/');
        $this->verifier->verify('payload', $this->algorithmIdentifier(Authority::SIGNATURE_OID), 'sig', 'not a cert');
    }

    /**
     * @return list<array{string}>
     */
    public static function unsupportedAlgorithmProvider(): array
    {
        return [
            ['1.2.840.113549.1.1.10'], // RSASSA-PSS, whose parameters openssl_verify cannot express
            ['1.2.840.113549.1.1.4'], // md5WithRSAEncryption
            ['1.2.3.4'],
        ];
    }

    #[DataProvider('unsupportedAlgorithmProvider')]
    public function testVerifyRejectsAnUnsupportedAlgorithm(string $oid): void
    {
        // Refusing to check beats accepting unchecked.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported signature algorithm/');
        $this->verifier->verify('payload', $this->algorithmIdentifier($oid), 'sig', Authority::ocsp()->certDer);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedAlgorithmIdentifierProvider(): array
    {
        $asn1 = new Asn1();

        return [
            'not a sequence' => [$asn1->encodeInteger(1)],
            'no oid inside' => [$asn1->encodeSequence($asn1->encodeInteger(1))],
        ];
    }

    #[DataProvider('malformedAlgorithmIdentifierProvider')]
    public function testVerifyRejectsAMalformedAlgorithmIdentifier(string $algorithmId): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signature AlgorithmIdentifier/');
        $this->verifier->verify('payload', $algorithmId, 'sig', Authority::ocsp()->certDer);
    }

    /**
     * The SHA-1 signature algorithms, refused unless the caller opts in.
     *
     * @return array<string, array{string}>
     */
    public static function sha1AlgorithmProvider(): array
    {
        return [
            'sha1WithRSAEncryption' => ['1.2.840.113549.1.1.5'],
            'ecdsa-with-SHA1' => ['1.2.840.10045.4.1'],
        ];
    }

    #[DataProvider('sha1AlgorithmProvider')]
    public function testVerifyRefusesSha1ByDefault(string $oid): void
    {
        // SHA-1 is refused unless the caller opts in, for a legacy responder that
        // emits nothing else.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Refusing the SHA-1 signature algorithm/');
        $this->verifier->verify('payload', $this->algorithmIdentifier($oid), 'sig', Authority::ocsp()->certDer);
    }

    public function testVerifyAcceptsSha1WhenTheCallerOptsIn(): void
    {
        $signed = 'payload';
        $signature = '';
        \openssl_sign($signed, $signature, $this->key(), OPENSSL_ALGO_SHA1);

        (new SignatureVerifier($this->asn1, allowSha1: true))->verify(
            $signed,
            $this->algorithmIdentifier('1.2.840.113549.1.1.5'),
            $signature,
            Authority::ocsp()->certDer,
        );

        $this->expectNotToPerformAssertions();
    }

    public function testSha1IsNotInTheDefaultAlgorithmTable(): void
    {
        // The two tables are the whole set of accepted algorithms.
        $this->assertSame(
            [
                '1.2.840.113549.1.1.11',
                '1.2.840.113549.1.1.12',
                '1.2.840.113549.1.1.13',
                '1.2.840.10045.4.3.2',
                '1.2.840.10045.4.3.3',
                '1.2.840.10045.4.3.4',
            ],
            \array_keys(SignatureVerifier::ALGORITHMS),
        );

        $this->assertSame(
            [
                '1.2.840.113549.1.1.5',
                '1.2.840.10045.4.1',
            ],
            \array_keys(SignatureVerifier::LEGACY_ALGORITHMS),
        );
    }

    /**
     * The private key behind the ocsp fixture certificate.
     */
    private function key(): \OpenSSLAsymmetricKey
    {
        $key = \openssl_pkey_get_private((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.key'));
        if (!$key instanceof \OpenSSLAsymmetricKey) {
            $this->fail('Unable to load the fixture key');
        }

        return $key;
    }

    private function algorithmIdentifier(string $oid): string
    {
        return $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($oid) . $this->asn1->encodeNull());
    }
}
