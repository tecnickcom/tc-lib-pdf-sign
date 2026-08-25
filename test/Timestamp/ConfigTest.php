<?php

declare(strict_types=1);

/**
 * ConfigTest.php
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

use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Timestamp\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Timestamp Config Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Config::class)]
final class ConfigTest extends TestCase
{
    public function testDefaults(): void
    {
        $cfg = new Config(host: 'https://tsa.example.org/tsr');
        $this->assertSame('https://tsa.example.org/tsr', $cfg->host);
        $this->assertSame('sha256', $cfg->hashAlgorithm);
        $this->assertSame('', $cfg->policyOid);
        $this->assertTrue($cfg->nonceEnabled);
        $this->assertSame(5, $cfg->timeout);
        $this->assertTrue($cfg->verifyPeer);
    }

    public function testAcceptsValidPolicyOid(): void
    {
        $cfg = new Config(host: 'https://tsa.example.org', policyOid: '1.2.3.4.5');
        $this->assertSame('1.2.3.4.5', $cfg->policyOid);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidHostProvider(): array
    {
        return [
            'empty' => [''],
            'no scheme' => ['tsa.example.org'],
            'unsupported scheme' => ['ftp://tsa.example.org'],
            'scheme only' => ['https://'],
            'whitespace' => ['  '],
        ];
    }

    #[DataProvider('invalidHostProvider')]
    public function testInvalidHostThrows(string $host): void
    {
        $this->expectException(Exception::class);
        new Config(host: $host);
    }

    public function testAcceptsPlainHttpHost(): void
    {
        $this->assertSame('http://tsa.internal:318', (new Config(host: 'http://tsa.internal:318'))->host);
    }

    public function testInvalidHashAlgorithmThrows(): void
    {
        $this->expectException(Exception::class);
        new Config(host: 'https://tsa.example.org', hashAlgorithm: 'md5');
    }

    public function testInvalidPolicyOidThrows(): void
    {
        $this->expectException(Exception::class);
        new Config(host: 'https://tsa.example.org', policyOid: 'not-an-oid');
    }

    public function testInvalidTimeoutThrows(): void
    {
        $this->expectException(Exception::class);
        new Config(host: 'https://tsa.example.org', timeout: 0);
    }

    public function testDebugInfoRedactsTheBasicAuthPassword(): void
    {
        // The password is a public readonly property, so __debugInfo() masks it.
        $secret = \str_rot13('f3perg');
        $cfg = new Config(host: 'https://tsa.example.org', username: 'user', password: $secret);

        $dump = \print_r($cfg, true);
        $this->assertStringNotContainsString($secret, $dump);
        $this->assertStringContainsString('***', $dump);
        $this->assertStringContainsString('user', $dump);

        // The value itself is still readable by the host that has to send it.
        $this->assertSame($secret, $cfg->password);
    }

    public function testDebugInfoLeavesAnAbsentPasswordEmpty(): void
    {
        $dump = \print_r(new Config(host: 'https://tsa.example.org'), true);
        $this->assertStringNotContainsString('***', $dump);
    }

    public function testTransportFieldsAreCarriedForTheHost(): void
    {
        // The library performs no network I/O; these are passed through so the
        // host can apply them to its own HTTP client.
        $cfg = new Config(
            host: 'https://tsa.example.org',
            timeout: 30,
            verifyPeer: false,
            username: 'user',
            cert: '/etc/ssl/ca.pem',
        );

        $this->assertSame(30, $cfg->timeout);
        $this->assertFalse($cfg->verifyPeer);
        $this->assertSame('user', $cfg->username);
        $this->assertSame('/etc/ssl/ca.pem', $cfg->cert);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidPolicyOidProvider(): array
    {
        return [
            'not an oid' => ['not-an-oid'],
            'root arc too large' => ['3.1.2'],
            'single arc' => ['1'],
            'trailing dot' => ['1.2.'],
        ];
    }

    #[DataProvider('invalidPolicyOidProvider')]
    public function testInvalidPolicyOidVariantsThrow(string $policyOid): void
    {
        $this->expectException(Exception::class);
        new Config(host: 'https://tsa.example.org', policyOid: $policyOid);
    }

    /**
     * Hosts an unanchored pattern would accept by reading only the authority.
     *
     * @return array<string, array{string}>
     */
    public static function unanchoredHostProvider(): array
    {
        return [
            'newline in the path' => ["https://tsa.example.org\n/evil"],
            'header injection' => ["http://tsa.example.org\r\nX-Injected: 1"],
            'trailing junk' => ['https://tsa.example.org  extra'],
            'tab in the path' => ["https://tsa.example.org/\tpath"],
            // PCRE matches $ before a final newline, so the end anchor has to be \z.
            'trailing newline after the path' => ["https://tsa.example.org/tsa\n"],
            'trailing newline after the authority' => ["https://tsa.example.org\n"],
            // \s is five whitespace octets, so an authority held to that alone
            // would let every other control octet through.
            'null byte in the authority' => ["https://tsa.exa\x00mple.org"],
            'control bytes in the authority' => ["https://tsa.example.org\x01\x02"],
            'delete byte in the authority' => ["https://tsa.example.org\x7F"],
        ];
    }

    #[DataProvider('unanchoredHostProvider')]
    public function testHostRejectsAnythingAfterTheAuthorityThatIsNotAUrl(string $host): void
    {
        // The value is handed to the host's HTTP client, which may interpolate it
        // into a request line or a header.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid TSA host/');
        new Config(host: $host);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validHostProvider(): array
    {
        return [
            'bare authority' => ['https://tsa.example.org'],
            'with a port' => ['https://tsa.example.org:3128'],
            'with a path' => ['http://tsa.example.org/tsa'],
            'with a query' => ['https://tsa.example.org/tsa?policy=1'],
        ];
    }

    #[DataProvider('validHostProvider')]
    public function testHostAcceptsOrdinaryUrls(string $host): void
    {
        $this->assertSame($host, (new Config(host: $host))->host);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function credentialWithAControlCharacterProvider(): array
    {
        return [
            'CRLF in the username' => ['username', "user\r\nX-Injected: 1"],
            'newline in the password' => ['password', "secret\nX-Injected: 1"],
            'NUL in the password' => ['password', "secret\x00"],
            'newline in the CA bundle path' => ['cert', "/etc/ssl/certs.pem\n"],
        ];
    }

    #[DataProvider('credentialWithAControlCharacterProvider')]
    public function testTransportCredentialsRejectAControlCharacter(string $field, string $value): void
    {
        // The three entries reach the same host client the endpoint does, so they
        // are held to the same control-character rule as URL_PATTERN.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/The TSA ' . $field . ' holds a control character/');
        new Config(...['host' => 'https://tsa.example.org', $field => $value]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function ordinaryCredentialProvider(): array
    {
        return [
            'plain' => ['s3cret'],
            'with a space' => ['correct horse battery staple'],
            'non-ASCII' => ['pässwörd'],
            'punctuation' => ['a:b@c/d?e#f'],
            'empty' => [''],
        ];
    }

    #[DataProvider('ordinaryCredentialProvider')]
    public function testTransportCredentialsAcceptOrdinaryValues(string $value): void
    {
        // Control characters alone are refused: a password may hold a space or a
        // non-ASCII character.
        $config = new Config(host: 'https://tsa.example.org', username: $value, password: $value, cert: $value);

        $this->assertSame($value, $config->username);
        $this->assertSame($value, $config->password);
        $this->assertSame($value, $config->cert);
    }
}
