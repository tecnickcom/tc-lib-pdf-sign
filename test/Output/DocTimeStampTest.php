<?php

declare(strict_types=1);

/**
 * DocTimeStampTest.php
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

namespace Test\Output;

use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Output\DocTimeStamp;
use Com\Tecnick\Pdf\Sign\Output\Signature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * DocTimeStamp Output Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(DocTimeStamp::class)]
final class DocTimeStampTest extends TestCase
{
    private DocTimeStamp $docTimeStamp;

    protected function setUp(): void
    {
        $this->docTimeStamp = new DocTimeStamp();
    }

    public function testValueObjectStructure(): void
    {
        $out = $this->docTimeStamp->valueObject(7);

        $this->assertStringStartsWith("7 0 obj\n", $out);
        $this->assertStringEndsWith(" >>\nendobj\n", $out);
        $this->assertStringContainsString('/Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161', $out);
        $this->assertStringContainsString(Signature::BYTE_RANGE_PLACEHOLDER, $out);
        $this->assertStringContainsString(
            '/Contents<' . \str_repeat('0', Signature::DEFAULT_CONTENTS_LENGTH) . '>',
            $out,
        );

        // A document timestamp is not a signature: no /Sig, /Reference, /M, or /V.
        $this->assertStringNotContainsString('/Type /Sig', $out);
        $this->assertStringNotContainsString('/Reference', $out);
        $this->assertStringNotContainsString('/M ', $out);
        $this->assertStringNotContainsString('/V ', $out);
    }

    public function testCustomContentsLength(): void
    {
        $out = $this->docTimeStamp->valueObject(2, 64);
        $this->assertStringContainsString('/Contents<' . \str_repeat('0', 64) . '>', $out);
        $this->assertStringNotContainsString(\str_repeat('0', 65), $out);
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidContentsLengthProvider(): array
    {
        return [
            'odd' => [4_001],
            'zero' => [0],
            'negative' => [-4],
            // As for a signature, bounded above so an absurd length throws rather
            // than exhausting memory.
            'past the ceiling' => [Signature::MAX_CONTENTS_LENGTH + 2],
            'PHP_INT_MAX rounded even' => [PHP_INT_MAX - 1],
        ];
    }

    #[DataProvider('invalidContentsLengthProvider')]
    public function testValueObjectRejectsAnUnusableContentsLength(int $length): void
    {
        $this->expectException(Exception::class);
        $this->docTimeStamp->valueObject(1, $length);
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidObjectNumberProvider(): array
    {
        return ['zero' => [0], 'negative' => [-7]];
    }

    #[DataProvider('invalidObjectNumberProvider')]
    public function testValueObjectRejectsANonPositiveObjectNumber(int $objectId): void
    {
        // As for a signature, the host's signing pass finds this object by its
        // own number.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid document timestamp object number/');
        $this->docTimeStamp->valueObject($objectId);
    }
}
