<?php

declare(strict_types=1);

/**
 * InteropTest.php
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
use Com\Tecnick\Pdf\Sign\Ocsp\Client as OcspClient;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Credentials;
use Test\Fixture\Der;

/**
 * CMS interoperability Test
 *
 * Checks emitted structures against OpenSSL rather than against this library's
 * own parser. The whole CMS is exercised: SignedData framing, the CertificateSet,
 * the SignerInfo, and the signature over the DER SET OF signed attributes.
 *
 * The protocol fixtures the codec tests validate against are assembled by the
 * same encoder, so they are checked here too: OpenSSL reads the CRL, the OCSP
 * response, and the timestamp token, and verifies the CRL signature against the
 * issuing certificate.
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversNothing]
final class InteropTest extends TestCase
{
    private const SIGNING_TIME = 1_700_000_000;

    /**
     * @var list<string>
     */
    private array $paths = [];

    protected function setUp(): void
    {
        if ($this->openssl() === null) {
            $this->markTestSkipped('the openssl command line tool is not available');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->paths as $path) {
            if (!\is_file($path)) {
                continue;
            }

            \unlink($path);
        }

        $this->paths = [];
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function credentialProvider(): array
    {
        return [
            'RSA SHA-256' => ['rsa', 'prime256v1', 'sha256'],
            'RSA SHA-512' => ['rsa', 'prime256v1', 'sha512'],
            'ECDSA P-256' => ['ec', 'prime256v1', 'sha256'],
            'ECDSA P-384' => ['ec', 'secp384r1', 'sha384'],
            'ECDSA P-521' => ['ec', 'secp521r1', 'sha512'],
        ];
    }

    #[DataProvider('credentialProvider')]
    public function testOpensslVerifiesTheDetachedCms(string $keyType, string $curve, string $digest): void
    {
        $cred = Credentials::make($keyType, $curve);
        if ($cred === null) {
            $this->markTestSkipped($keyType . ' (' . $curve . ') key generation is not available');
        }

        $content = 'the ByteRange-covered document bytes';
        $cms = (new Builder())->sign($content, $cred['cert_der'], $cred['key'], [], $digest, self::SIGNING_TIME);

        $cmsPath = $this->write($cms);
        $contentPath = $this->write($content);
        $certPath = $this->write($cred['cert_pem']);

        // -noverify: the fixture is self-signed, so chain building is out of scope;
        // the cryptographic verification of the SignerInfo still runs.
        $output = [];
        $status = 0;
        \exec(
            \escapeshellarg((string) $this->openssl())
            . ' cms -verify -binary -inform DER'
            . ' -in '
            . \escapeshellarg($cmsPath)
            . ' -content '
            . \escapeshellarg($contentPath)
            . ' -certfile '
            . \escapeshellarg($certPath)
            . ' -noverify -out /dev/null 2>&1',
            $output,
            $status,
        );

        $this->assertSame(0, $status, 'openssl cms -verify failed: ' . \implode("\n", $output));
    }

    public function testOpensslParsesTheWholeStructure(): void
    {
        $cred = Credentials::make('rsa');
        if ($cred === null) {
            $this->markTestSkipped('RSA key generation is not available');
        }

        $chain = Credentials::make('rsa', 'prime256v1', 'tc-lib-pdf-sign chain');
        if ($chain === null) {
            $this->markTestSkipped('RSA key generation is not available');
        }

        $cms = (new Builder())->sign(
            'content',
            $cred['cert_der'],
            $cred['key'],
            [$chain['cert_der']],
            'sha256',
            self::SIGNING_TIME,
        );

        $output = [];
        $status = 0;
        \exec(
            \escapeshellarg((string) $this->openssl())
            . ' asn1parse -inform DER -in '
            . \escapeshellarg($this->write($cms))
            . ' 2>&1',
            $output,
            $status,
        );

        $text = \implode("\n", $output);
        $this->assertSame(0, $status, 'openssl asn1parse failed: ' . $text);

        // A structural error anywhere in the DER surfaces here as a parse error.
        $this->assertStringNotContainsString('Error in encoding', $text);
        $this->assertStringNotContainsString('BAD OBJECT', $text);

        // OpenSSL names the attributes and OIDs the profile requires, which it does
        // only when their OIDs are encoded correctly.
        $this->assertStringContainsString(':pkcs7-signedData', $text);
        $this->assertStringContainsString(':contentType', $text);
        $this->assertStringContainsString(':messageDigest', $text);
        $this->assertStringContainsString(':id-smime-aa-signingCertificateV2', $text);
    }

    public function testOpensslAcceptsTheFixtureCrl(): void
    {
        // The CRL fixtures are assembled by this library's own encoder, so openssl
        // is the independent check: it verifies the signature against the issuer.
        $asn1 = new Asn1();
        $crlPath = $this->write((new Der($asn1, Authority::ocsp()))->crl());
        $caPath = $this->write(Authority::ocsp()->certPem);

        $output = [];
        $status = 0;
        \exec(
            \escapeshellarg((string) $this->openssl())
            . ' crl -inform DER -in '
            . \escapeshellarg($crlPath)
            . ' -CAfile '
            . \escapeshellarg($caPath)
            . ' -noout -text 2>&1',
            $output,
            $status,
        );

        $joined = \implode("\n", $output);
        $this->assertSame(0, $status, 'openssl crl failed: ' . $joined);
        $this->assertStringContainsString('verify OK', $joined);
        $this->assertStringContainsString('tc-lib-pdf-sign root CA', $joined);
    }

    public function testOpensslParsesTheFixtureOcspResponse(): void
    {
        $asn1 = new Asn1();
        $der = new Der($asn1, Authority::ocsp());
        $ocsp = new OcspClient($asn1);

        $caDer = Authority::ocsp()->certDer;
        $leafDer = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_leaf.pem'));
        $responsePath = $this->write($der->ocspResponse($ocsp->build($caDer, $leafDer)->certId));

        $output = [];
        $status = 0;
        \exec(
            \escapeshellarg((string) $this->openssl())
            . ' ocsp -respin '
            . \escapeshellarg($responsePath)
            . ' -resp_text -noverify 2>&1',
            $output,
            $status,
        );

        $joined = \implode("\n", $output);
        $this->assertSame(0, $status, 'openssl ocsp failed: ' . $joined);
        $this->assertStringContainsString('Basic OCSP Response', $joined);
        $this->assertStringContainsString('Cert Status: good', $joined);
        $this->assertStringContainsString('tc-lib-pdf-sign root CA', $joined);
    }

    public function testOpensslParsesTheFixtureTimestampToken(): void
    {
        $asn1 = new Asn1();
        $der = new Der($asn1, Authority::ocsp());
        $token = $der->signedTimestampToken($der->tstInfo(\hash('sha256', 'payload', true), '2.16.840.1.101.3.4.2.1'));

        $output = [];
        $status = 0;
        \exec(
            \escapeshellarg((string) $this->openssl())
            . ' ts -reply -in '
            . \escapeshellarg($this->write($token))
            . ' -token_in -text 2>&1',
            $output,
            $status,
        );

        $joined = \implode("\n", $output);
        $this->assertSame(0, $status, 'openssl ts failed: ' . $joined);
        $this->assertStringContainsString('Hash Algorithm: sha256', $joined);

        // openssl prints the imprint as a hex dump, so it is compared byte by byte.
        $imprint = \str_split(\hash('sha256', 'payload'), 2);
        foreach ($imprint as $byte) {
            $this->assertStringContainsString($byte, \strtolower($joined));
        }
    }

    /**
     * Write a payload to a temporary file scheduled for removal.
     */
    private function write(string $data): string
    {
        $path = (string) \tempnam(\sys_get_temp_dir(), 'tclibpdfsign');
        $this->paths[] = $path;
        \file_put_contents($path, $data);

        return $path;
    }

    /**
     * Locate the openssl command line tool, or null when it is not installed.
     */
    private function openssl(): ?string
    {
        $output = [];
        $status = 0;
        \exec('command -v openssl 2>/dev/null', $output, $status);

        return $status === 0 && isset($output[0]) && $output[0] !== '' ? $output[0] : null;
    }
}
