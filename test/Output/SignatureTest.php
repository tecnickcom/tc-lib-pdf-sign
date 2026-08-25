<?php

declare(strict_types=1);

/**
 * SignatureTest.php
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-sign
 *
 * This file is part of tc-lib-pdf-sign software library.
 */

namespace Test\Output;

use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Output\PdfString;
use Com\Tecnick\Pdf\Sign\Output\Signature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Signature Output Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link        https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Signature::class)]
#[CoversClass(PdfString::class)]
final class SignatureTest extends TestCase
{
    private Signature $signature;

    protected function setUp(): void
    {
        $this->signature = new Signature();
    }

    private const DOCMDP_REFERENCE =
        ' /Reference [ << /Type /SigRef /TransformMethod /DocMDP'
            . ' /TransformParams << /Type /TransformParams /P 2 /V /1.2 >> >> ]';

    private const DATE_VALUE = "(D:20231114221320+00'00')";

    public function testValueObjectWithReferenceAndInfo(): void
    {
        $out = $this->signature->valueObject(
            12,
            'ETSI.CAdES.detached',
            self::DOCMDP_REFERENCE,
            ['Name' => 'Jane Doe', 'Location' => 'Rome', 'Reason' => 'Approval', 'ContactInfo' => 'jane@example.org'],
            self::DATE_VALUE,
        );

        $this->assertStringStartsWith("12 0 obj\n", $out);
        $this->assertStringEndsWith(" >>\nendobj\n", $out);
        $this->assertStringContainsString('/Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached', $out);
        $this->assertStringContainsString(Signature::BYTE_RANGE_PLACEHOLDER, $out);
        $this->assertStringContainsString(
            '/Contents<' . \str_repeat('0', Signature::DEFAULT_CONTENTS_LENGTH) . '>',
            $out,
        );
        $this->assertStringContainsString(self::DOCMDP_REFERENCE, $out);
        $this->assertStringContainsString('/Name (Jane Doe)', $out);
        $this->assertStringContainsString('/Location (Rome)', $out);
        $this->assertStringContainsString('/Reason (Approval)', $out);
        $this->assertStringContainsString('/ContactInfo (jane@example.org)', $out);
        // The /M date token is appended verbatim (already encoded by the caller).
        $this->assertStringContainsString(' /M ' . self::DATE_VALUE . ' >>', $out);
    }

    public function testEmptyReferenceIsOmitted(): void
    {
        $out = $this->signature->valueObject(3, 'ETSI.CAdES.detached', '', [], self::DATE_VALUE);
        $this->assertStringNotContainsString('/Reference', $out);
        $this->assertStringNotContainsString('/Name', $out);
        $this->assertStringContainsString('/SubFilter /ETSI.CAdES.detached', $out);
    }

    public function testCustomContentsLength(): void
    {
        $out = $this->signature->valueObject(1, 'adbe.pkcs7.detached', '', [], self::DATE_VALUE, 128);
        $this->assertStringContainsString('/Contents<' . \str_repeat('0', 128) . '>', $out);
        $this->assertStringNotContainsString(\str_repeat('0', 129), $out);
    }

    public function testDefaultEncoderEscapesLiteralStrings(): void
    {
        $out = $this->signature->valueObject(1, 'adbe.pkcs7.detached', '', ['Name' => 'A (B) \\ C'], self::DATE_VALUE);
        $this->assertStringContainsString('/Name (A \\(B\\) \\\\ C)', $out);
    }

    public function testUsesInjectedStringEncoder(): void
    {
        $encoder = static fn(string $text, int $_objectId): string => '<' . \bin2hex($text) . '>';
        $out = $this->signature->valueObject(
            5,
            'ETSI.CAdES.detached',
            '',
            ['Reason' => 'Hi'],
            self::DATE_VALUE,
            Signature::DEFAULT_CONTENTS_LENGTH,
            $encoder,
        );
        $this->assertStringContainsString('/Reason <' . \bin2hex('Hi') . '>', $out);
    }

    public function testRejectsAnInfoValueThatIsNotAString(): void
    {
        // Typed loosely on purpose: a value that is not a string would reach the
        // string encoder as a TypeError rather than an Exception.
        /** @var array<string, string> $info */
        $info = ['Name' => 42];

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signature info value: Name/');
        $this->signature->valueObject(1, 'adbe.pkcs7.detached', '', $info, self::DATE_VALUE);
    }

    public function testRejectsNonStringEncoderResult(): void
    {
        $encoder = static fn(string $_text, int $objectId): int => $objectId;
        $this->expectException(Exception::class);
        $this->signature->valueObject(
            5,
            'ETSI.CAdES.detached',
            '',
            ['Reason' => 'Hi'],
            self::DATE_VALUE,
            Signature::DEFAULT_CONTENTS_LENGTH,
            $encoder,
        );
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidContentsLengthProvider(): array
    {
        return [
            'odd' => [11_741],
            'zero' => [0],
            'negative' => [-2],
            'one' => [1],
            // Bounded above too, str_repeat() answering an absurd length by
            // exhausting memory rather than throwing.
            'past the ceiling' => [Signature::MAX_CONTENTS_LENGTH + 2],
            'PHP_INT_MAX rounded even' => [PHP_INT_MAX - 1],
        ];
    }

    #[DataProvider('invalidContentsLengthProvider')]
    public function testValueObjectRejectsAnUnusableContentsLength(int $length): void
    {
        // An odd number of hex digits is read with a trailing zero appended
        // (ISO 32000-1 section 7.3.4.3), shifting the reserved window by a nibble.
        $this->expectException(Exception::class);
        $this->signature->valueObject(1, 'ETSI.CAdES.detached', '', [], '(D:2026)', $length);
    }

    public function testValueObjectAcceptsTheLargestContentsLength(): void
    {
        $out = $this->signature->valueObject(
            1,
            'ETSI.CAdES.detached',
            '',
            [],
            '(D:2026)',
            Signature::MAX_CONTENTS_LENGTH,
        );

        $this->assertStringContainsString('/Contents<' . \str_repeat('0', Signature::MAX_CONTENTS_LENGTH) . '>', $out);
    }

    public function testValueObjectAcceptsTheDefaultContentsLength(): void
    {
        $out = $this->signature->valueObject(1, 'ETSI.CAdES.detached', '', [], '(D:2026)');
        $this->assertStringContainsString(
            '/Contents<' . \str_repeat('0', Signature::DEFAULT_CONTENTS_LENGTH) . '>',
            $out,
        );
        $this->assertSame(0, Signature::DEFAULT_CONTENTS_LENGTH % 2);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidSubFilterProvider(): array
    {
        return [
            'empty' => [''],
            'with space' => ['ETSI.CAdES detached'],
            'dictionary injection' => ['x >> /Foo <<'],
            'delimiter' => ['a/b'],
        ];
    }

    #[DataProvider('invalidSubFilterProvider')]
    public function testValueObjectRejectsAMalformedSubFilter(string $subFilter): void
    {
        $this->expectException(Exception::class);
        $this->signature->valueObject(1, $subFilter, '', [], '(D:2026)');
    }

    #[DataProvider('invalidSubFilterProvider')]
    public function testObjectHeadRejectsAMalformedSubFilter(string $subFilter): void
    {
        // Both names are interpolated into the dictionary as written, so they are
        // held to the name character set. Note where the injected token lands: a
        // /Contents ahead of the real placeholder shifts the reserved window.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid \/SubFilter/');
        Signature::objectHead(1, 'Sig', $subFilter, 4, 'signature');
    }

    #[DataProvider('invalidSubFilterProvider')]
    public function testObjectHeadRejectsAMalformedType(string $type): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid \/Type/');
        Signature::objectHead(1, $type, 'ETSI.CAdES.detached', 4, 'signature');
    }

    public function testInfoStringsWithNonAsciiUseUtf16(): void
    {
        // Raw UTF-8 in a literal string is read as PDFDocEncoding and renders as
        // mojibake, so the fallback switches to a UTF-16BE hex string.
        $out = $this->signature->valueObject(1, 'adbe.pkcs7.detached', '', ['Name' => 'Nicola Asùni'], '(D:2026)');

        $this->assertStringContainsString('/Name <FEFF', $out);
        $this->assertStringNotContainsString('Asùni', $out);
    }

    public function testInfoStringsWithControlCharactersUseUtf16(): void
    {
        // A raw CR or CRLF inside a literal string is folded to a single LF by a
        // conforming reader (ISO 32000-1 section 7.3.4.2), so the hex form is used.
        $out = $this->signature->valueObject(1, 'adbe.pkcs7.detached', '', ['Reason' => "a\rb\nc"], '(D:2026)');

        $this->assertStringContainsString('/Reason <FEFF0061000D0062000A0063>', $out);
    }

    public function testValueObjectOmitsTheDateWhenThereIsNone(): void
    {
        // A key with no value is not a dictionary entry, so an empty date omits the
        // /M entry.
        $out = $this->signature->valueObject(1, 'adbe.pkcs7.detached', '', [], '');

        $this->assertStringNotContainsString('/M', $out);
        $this->assertStringEndsWith(" >>\nendobj\n", $out);
    }

    public function testValueObjectKeepsTheDateWhenThereIsOne(): void
    {
        $out = $this->signature->valueObject(1, 'adbe.pkcs7.detached', '', [], '(D:20260824120000Z)');

        $this->assertStringContainsString(' /M (D:20260824120000Z) >>', $out);
    }

    #[DataProvider('invalidObjectNumberProvider')]
    public function testValueObjectRejectsANonPositiveObjectNumber(int $objectId): void
    {
        // ISO 32000-1 section 7.3.10, as Widget::annotation() and Dss::emit() have
        // it. The number also derives the string encryption key.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid signature object number/');
        $this->signature->valueObject($objectId, 'adbe.pkcs7.detached', '', [], '');
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidObjectNumberProvider(): array
    {
        return ['zero' => [0], 'negative' => [-7]];
    }
}
