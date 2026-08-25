<?php

declare(strict_types=1);

/**
 * PdfStringTest.php
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

namespace Test\Output;

use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Output\PdfString;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * PdfString Test
 *
 * @since     2026-08-24
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(PdfString::class)]
final class PdfStringTest extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function literalProvider(): array
    {
        return [
            'plain' => ['Nicola Asuni', '(Nicola Asuni)'],
            'empty' => ['', '()'],
            'backslash' => ['a\\b', '(a\\\\b)'],
            'parentheses' => ['a(b)c', '(a\\(b\\)c)'],
            'all printable ascii' => [' ~!@#$%^&*_+=[]{}|;:\'",.<>/?', '( ~!@#$%^&*_+=[]{}|;:\'",.<>/?)'],
        ];
    }

    #[DataProvider('literalProvider')]
    public function testFallbackEmitsAnEscapedLiteralString(string $text, string $expected): void
    {
        $this->assertSame($expected, PdfString::encode($text, 1));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function utf16Provider(): array
    {
        return [
            'latin-1 accent' => ['Asùni', '<FEFF0041007300F9006E0069>'],
            'euro sign' => ['€', '<FEFF20AC>'],
            // Outside the BMP: encoded as a surrogate pair.
            'emoji' => ["\u{1F512}", '<FEFFD83DDD12>'],
            'mixed' => ["a\u{00E9}", '<FEFF006100E9>'],
        ];
    }

    #[DataProvider('utf16Provider')]
    public function testFallbackEmitsUtf16ForNonAscii(string $text, string $expected): void
    {
        $this->assertSame($expected, PdfString::encode($text, 1));
    }

    public function testFallbackReplacesInvalidUtf8(): void
    {
        // Never emit raw bytes that would make the token unreadable.
        $encoded = PdfString::encode("\xC3\x28", 1);

        $this->assertStringStartsWith('<FEFF', $encoded);
        $this->assertStringEndsWith('>', $encoded);
        $this->assertSame(1, \preg_match('/^<[0-9A-F]+>$/', $encoded));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function controlCharacterProvider(): array
    {
        return [
            // A raw CR or CRLF in a literal string is folded to a single LF by a
            // conforming reader (ISO 32000-1 section 7.3.4.2), so the hex form is used.
            'carriage return' => ["a\rb", '<FEFF0061000D0062>'],
            'line feed' => ["a\nb", '<FEFF0061000A0062>'],
            'crlf' => ["a\r\nb", '<FEFF0061000D000A0062>'],
            'tab' => ["a\tb", '<FEFF006100090062>'],
            'nul' => ["a\x00", '<FEFF00610000>'],
            'backspace' => ["a\x08b", '<FEFF006100080062>'],
        ];
    }

    #[DataProvider('controlCharacterProvider')]
    public function testFallbackEmitsControlCharactersAsHex(string $text, string $expected): void
    {
        $this->assertSame($expected, PdfString::encode($text, 1));
    }

    public function testEncoderOverridesTheFallback(): void
    {
        $encoder = static fn(string $text, int $objectId): string => '<' . \bin2hex($text . $objectId) . '>';

        $this->assertSame('<' . \bin2hex('x7') . '>', PdfString::encode('x', 7, $encoder));
    }

    public function testEncoderMustReturnAString(): void
    {
        $this->expectException(Exception::class);
        PdfString::encode('x', 1, static fn(string $_text, int $_objectId): int => 1);
    }

    public function testInvalidUtf8ReplacesOnlyTheBadBytes(): void
    {
        // A UTF-8 pattern fails for the whole subject on the first bad byte, so the
        // characters around a stray byte have to survive it.
        $latin1 = "M\xFCller GmbH";

        $this->assertSame('<FEFF004DFFFD006C006C0065007200200047006D00620048>', PdfString::encode($latin1, 1));
    }

    public function testInvalidUtf8AtTheEndIsReplaced(): void
    {
        // A truncated multi-byte sequence: the lead byte alone is not a character.
        $this->assertSame('<FEFF0061FFFD>', PdfString::encode("a\xC3", 1));
    }

    public function testValidUtf8IsUnaffected(): void
    {
        $this->assertSame('<FEFF004D00FC006C006C0065007200200047006D00620048>', PdfString::encode('Müller GmbH', 1));
    }

    /**
     * Byte sequences a decoder must not accept (Unicode 15 table 3-7).
     *
     * @return array<string, array{string, string}>
     */
    public static function invalidUtf8Provider(): array
    {
        return [
            'overlong two-byte form' => ["a\xC0\xAFb", '<FEFF0061FFFDFFFD0062>'],
            'surrogate half' => ["a\xED\xA0\x80b", '<FEFF0061FFFDFFFDFFFD0062>'],
            'above U+10FFFF' => ["\xF4\x90\x80\x80", '<FEFFFFFDFFFDFFFDFFFD>'],
            'bare continuation byte' => ["a\x80b", '<FEFF0061FFFD0062>'],
            'truncated four-byte form' => ["\xF0\x9F\x98", '<FEFFFFFDFFFDFFFD>'],
            'bad third byte' => ["\xE0\xA0\x41", '<FEFFFFFDFFFD0041>'],
            'lead byte 0xFF' => ["\xFFa", '<FEFFFFFD0061>'],
        ];
    }

    #[DataProvider('invalidUtf8Provider')]
    public function testInvalidSequencesBecomeReplacementCharacters(string $text, string $expected): void
    {
        $this->assertSame($expected, PdfString::encode($text, 1));
    }

    public function testAstralPlaneCharactersBecomeASurrogatePair(): void
    {
        // U+1F600, encoded as the UTF-16BE pair D83D DE00.
        $this->assertSame('<FEFFD83DDE00>', PdfString::encode("\xF0\x9F\x98\x80", 1));
    }
}
