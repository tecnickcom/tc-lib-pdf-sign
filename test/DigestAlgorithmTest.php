<?php

declare(strict_types=1);

/**
 * DigestAlgorithmTest.php
 *
 * @since     2026-07-17
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

use Com\Tecnick\Pdf\Sign\Config;
use Com\Tecnick\Pdf\Sign\DigestAlgorithm;
use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Timestamp\Client as TimestampClient;
use Com\Tecnick\Pdf\Sign\Timestamp\Config as TimestampConfig;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * DigestAlgorithm enum test
 *
 * @since     2026-07-17
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(DigestAlgorithm::class)]
final class DigestAlgorithmTest extends TestCase
{
    public function testCaseBackingValues(): void
    {
        $this->assertSame('sha256', DigestAlgorithm::Sha256->value);
        $this->assertSame('sha384', DigestAlgorithm::Sha384->value);
        $this->assertSame('sha512', DigestAlgorithm::Sha512->value);
    }

    public function testBothConfigConstantsStayEqualToTheEnum(): void
    {
        // The constants are derived from the enum, but a constant expression cannot
        // iterate the cases, so both lists are kept in step by hand.
        $this->assertSame(DigestAlgorithm::values(), Config::DIGEST_ALGORITHMS);
        $this->assertSame(DigestAlgorithm::values(), TimestampConfig::HASH_ALGORITHMS);
    }

    public function testTheCodecsReadTheirOidsFromTheEnum(): void
    {
        // The RFC 3161 request and the CMS digestAlgorithm both read the OID from
        // the enum. Each one is the NIST OID RFC 5754 section 2 names.
        $client = new TimestampClient(new TimestampConfig('https://tsa.example.org'));

        $expected = [
            'sha256' => '2.16.840.1.101.3.4.2.1',
            'sha384' => '2.16.840.1.101.3.4.2.2',
            'sha512' => '2.16.840.1.101.3.4.2.3',
        ];

        foreach (DigestAlgorithm::cases() as $case) {
            $this->assertSame($expected[$case->value] ?? null, $case->oid(), $case->value . ' OID');
            $this->assertSame($case->oid(), $client->hashAlgorithmOid($case->value), $case->value . ' request OID');
            $this->assertSame($case, DigestAlgorithm::tryFromOid($case->oid()), $case->value . ' round trip');
        }

        $this->assertNull(DigestAlgorithm::tryFromOid('1.3.14.3.2.26'));
    }

    public function testValuesMatchCases(): void
    {
        $values = \array_map(static fn(DigestAlgorithm $case): string => $case->value, DigestAlgorithm::cases());
        $this->assertSame($values, DigestAlgorithm::values());
        $this->assertSame(['sha256', 'sha384', 'sha512'], DigestAlgorithm::values());
    }

    public function testBothConfigsAcceptEveryCase(): void
    {
        foreach (DigestAlgorithm::cases() as $case) {
            $this->assertSame($case->value, (new Config(digestAlgorithm: $case))->digestAlgorithm);
            $this->assertSame($case->value, (new TimestampConfig('https://tsa.example.org', $case))->hashAlgorithm);
        }
    }

    public function testFromLooseCanonical(): void
    {
        $this->assertSame(DigestAlgorithm::Sha256, DigestAlgorithm::fromLoose('sha256'));
        $this->assertSame(DigestAlgorithm::Sha512, DigestAlgorithm::fromLoose('sha512'));
    }

    public function testFromLoosePassesThroughEnumInstance(): void
    {
        $this->assertSame(DigestAlgorithm::Sha384, DigestAlgorithm::fromLoose(DigestAlgorithm::Sha384));
    }

    public function testFromLooseRoundTrip(): void
    {
        foreach (DigestAlgorithm::cases() as $case) {
            $this->assertSame($case, DigestAlgorithm::fromLoose($case->value));
        }
    }

    public function testFromLooseUnknownThrows(): void
    {
        $this->expectException(Exception::class);
        DigestAlgorithm::fromLoose('md5');
    }

    public function testConfigAcceptsEnum(): void
    {
        $cfg = new Config(Config::PROFILE_LEGACY, DigestAlgorithm::Sha384);
        $this->assertSame('sha384', $cfg->digestAlgorithm);
    }

    public function testTimestampConfigAcceptsEnum(): void
    {
        $cfg = new TimestampConfig(host: 'https://tsa.example.org', hashAlgorithm: DigestAlgorithm::Sha512);
        $this->assertSame('sha512', $cfg->hashAlgorithm);
    }

    public function testDigestLengthMatchesTheHashOutput(): void
    {
        foreach (DigestAlgorithm::cases() as $case) {
            $this->assertSame(
                \strlen(\hash($case->value, '', true)),
                $case->digestLength(),
                $case->value . ' digest length',
            );
        }
    }
}
