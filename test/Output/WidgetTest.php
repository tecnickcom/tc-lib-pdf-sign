<?php

declare(strict_types=1);

/**
 * WidgetTest.php
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
use Com\Tecnick\Pdf\Sign\Output\Widget;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Widget Output Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Widget::class)]
final class WidgetTest extends TestCase
{
    private Widget $widget;

    protected function setUp(): void
    {
        $this->widget = new Widget();
    }

    public function testSignedFieldWidget(): void
    {
        $out = $this->widget->annotation(8, '10.0 20.0 110.0 60.0', 5, 'Signature', 9, ' /AS /N /AP << /N 20 0 R >>');

        $this->assertStringStartsWith("8 0 obj\n", $out);
        $this->assertStringEndsWith(" >>\nendobj\n", $out);
        $this->assertStringContainsString('/Type /Annot /Subtype /Widget', $out);
        $this->assertStringContainsString('/Rect [10.0 20.0 110.0 60.0]', $out);
        $this->assertStringContainsString('/P 5 0 R', $out);
        $this->assertStringContainsString('/F 4 /FT /Sig', $out);
        $this->assertStringContainsString('/T (Signature)', $out);
        $this->assertStringContainsString('/Ff 0', $out);
        $this->assertStringContainsString('/AS /N /AP << /N 20 0 R >>', $out);
        $this->assertStringContainsString('/V 9 0 R', $out);
    }

    public function testEmptyFieldWidgetHasNoValueOrAppearance(): void
    {
        $out = $this->widget->annotation(4, '0 0 100 40', 5, 'Reviewer [002]');
        $this->assertStringContainsString('/T (Reviewer [002])', $out);
        $this->assertStringNotContainsString('/V ', $out);
        $this->assertStringNotContainsString('/AP', $out);
    }

    public function testUsesInjectedStringEncoder(): void
    {
        $encoder = static fn(string $text, int $_objectId): string => '<' . \bin2hex($text) . '>';
        $out = $this->widget->annotation(4, '0 0 1 1', 5, 'Sig', null, '', $encoder);
        $this->assertStringContainsString('/T <' . \bin2hex('Sig') . '>', $out);
    }

    public function testRejectsNonStringEncoderResult(): void
    {
        $encoder = static fn(string $_text, int $objectId): int => $objectId;
        $this->expectException(Exception::class);
        $this->widget->annotation(4, '0 0 1 1', 5, 'Sig', null, '', $encoder);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidRectangleProvider(): array
    {
        return [
            'three numbers' => ['0 0 100'],
            'five numbers' => ['0 0 100 40 5'],
            'dictionary injection' => ['0 0 1 1] /Extra <<'],
            'not numeric' => ['a b c d'],
            'trailing space' => ['0 0 1 1 '],
        ];
    }

    #[DataProvider('invalidRectangleProvider')]
    public function testAnnotationRejectsAMalformedRectangle(string $rect): void
    {
        $this->expectException(Exception::class);
        $this->widget->annotation(4, $rect, 5, 'Sig');
    }

    public function testAnnotationTreatsAnEmptyRectangleAsInvisible(): void
    {
        // /Rect [] is not a valid annotation, so an invisible field gets the
        // degenerate rectangle rather than a malformed dictionary.
        $out = $this->widget->annotation(4, '', 5, 'Sig');
        $this->assertStringContainsString('/Rect [0 0 0 0]', $out);
    }

    public function testAnnotationAcceptsNegativeAndDecimalCoordinates(): void
    {
        $out = $this->widget->annotation(4, '-10.5 -20 100.25 40', 5, 'Sig');
        $this->assertStringContainsString('/Rect [-10.5 -20 100.25 40]', $out);
    }

    /**
     * @return list<array{string}>
     */
    public static function validRectangleProvider(): array
    {
        // ISO 32000-1 section 7.3.3 admits a leading sign and a decimal point on
        // either side of the digits.
        return [
            ['0 0 100 200'],
            ['.5 0 100 200'],
            ['1. 0 1 2'],
            ['+5 -3 1 2'],
            ['-3.62 0 4. .002'],
        ];
    }

    #[DataProvider('validRectangleProvider')]
    public function testAnnotationAcceptsEveryPdfRealForm(string $rect): void
    {
        $this->assertStringContainsString('/Rect [' . $rect . ']', (new Widget())->annotation(1, $rect, 2, 'field'));
    }

    /**
     * Forms that look numeric but are not PDF numbers.
     *
     * @return array<string, array{string}>
     */
    public static function nonPdfNumberRectangleProvider(): array
    {
        return [
            'exponent notation' => ['0 0 1e2 3'],
            'bare decimal point' => ['. . . .'],
            'double sign' => ['+-1 0 1 2'],
        ];
    }

    #[DataProvider('nonPdfNumberRectangleProvider')]
    public function testAnnotationRejectsNonPdfNumbers(string $rect): void
    {
        $this->expectException(Exception::class);
        (new Widget())->annotation(1, $rect, 2, 'field');
    }

    /**
     * Object numbers that are not valid indirect references.
     *
     * @return array<string, array{int, int, int|null}>
     */
    public static function invalidObjectNumberProvider(): array
    {
        return [
            'annotation object' => [0, 2, null],
            'page object' => [1, 0, null],
            'negative page object' => [1, -3, null],
            'value object' => [1, 2, 0],
        ];
    }

    #[DataProvider('invalidObjectNumberProvider')]
    public function testAnnotationRejectsNonPositiveObjectNumbers(int $objectId, int $page, ?int $value): void
    {
        // ISO 32000-1 section 7.3.10: an indirect reference names a positive object
        // number, and these are interpolated into the dictionary as written.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/object number/');
        (new Widget())->annotation($objectId, '0 0 1 1', $page, 'field', $value);
    }

    public function testAnnotationRejectsAFieldNameWithAPeriod(): void
    {
        // ISO 32000-1 section 12.7.3.2: a period separates the components of a fully
        // qualified field name, so a partial name cannot contain one.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/field name/');
        (new Widget())->annotation(1, '0 0 1 1', 2, 'a.b.c');
    }
}
