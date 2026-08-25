<?php

declare(strict_types=1);

/**
 * Asn1Test.php
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
use Com\Tecnick\Pdf\Sign\Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Asn1 Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Asn1::class)]
final class Asn1Test extends TestCase
{
    private Asn1 $asn1;

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
    }

    public function testEncodeLengthShortForm(): void
    {
        $this->assertSame("\x05", $this->asn1->encodeLength(5));
        $this->assertSame("\x7F", $this->asn1->encodeLength(127));
    }

    public function testEncodeLengthLongForm(): void
    {
        $this->assertSame("\x81\x80", $this->asn1->encodeLength(128));
        $this->assertSame("\x82\x01\x00", $this->asn1->encodeLength(256));
    }

    public function testEncodeInteger(): void
    {
        $this->assertSame("\x02\x01\x00", $this->asn1->encodeInteger(0));
        $this->assertSame("\x02\x01\x7F", $this->asn1->encodeInteger(127));
        $this->assertSame("\x02\x02\x00\xFF", $this->asn1->encodeInteger(255));
        $this->assertSame("\x02\x02\x01\x00", $this->asn1->encodeInteger(256));
    }

    public function testEncodeIntegerBytesTrimsAndPads(): void
    {
        $this->assertSame("\x02\x01\x7F", $this->asn1->encodeIntegerBytes("\x00\x7F"));
        $this->assertSame("\x02\x02\x00\x80", $this->asn1->encodeIntegerBytes("\x80"));
    }

    public function testEncodeBoolean(): void
    {
        $this->assertSame("\x01\x01\xFF", $this->asn1->encodeBoolean(true));
        $this->assertSame("\x01\x01\x00", $this->asn1->encodeBoolean(false));
    }

    public function testEncodeNull(): void
    {
        $this->assertSame("\x05\x00", $this->asn1->encodeNull());
    }

    public function testEncodeOctetStringSequenceSet(): void
    {
        $this->assertSame("\x04\x02AB", $this->asn1->encodeOctetString('AB'));
        $this->assertSame("\x30\x02AB", $this->asn1->encodeSequence('AB'));
        $this->assertSame("\x31\x02AB", $this->asn1->encodeSet('AB'));
    }

    public function testEncodeContext(): void
    {
        $this->assertSame("\xA0\x02AB", $this->asn1->encodeContext(0, 'AB'));
        $this->assertSame("\xA3\x02AB", $this->asn1->encodeContext(3, 'AB'));
    }

    public function testEncodeObjectIdentifier(): void
    {
        // sha256WithRSAEncryption: 1.2.840.113549.1.1.11
        $this->assertSame(
            '06092a864886f70d01010b',
            \bin2hex($this->asn1->encodeObjectIdentifier('1.2.840.113549.1.1.11')),
        );
    }

    public function testReadTlvRoundTrip(): void
    {
        $der = $this->asn1->encodeSequence($this->asn1->encodeInteger(256));
        $offset = 0;
        $tlv = $this->asn1->readTlv($der, $offset);
        $this->assertSame(0x30, $tlv['tag']);
        $this->assertSame(\strlen($der), $offset);
        $this->assertSame($der, $tlv['raw']);

        $inner = 0;
        $intTlv = $this->asn1->readTlv($tlv['value'], $inner);
        $this->assertSame(0x02, $intTlv['tag']);
        $this->assertSame(256, $this->asn1->decodeInteger($intTlv['value']));
    }

    public function testReadTlvRejectsTruncatedData(): void
    {
        $this->expectException(Exception::class);
        $offset = 0;
        $this->asn1->readTlv("\x30\x05\x00", $offset);
    }

    public function testDecodeIntegerRejectsEmpty(): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeInteger('');
    }

    public function testEncodeIntegerBytesEmptyInputYieldsZero(): void
    {
        $this->assertSame("\x02\x01\x00", $this->asn1->encodeIntegerBytes(''));
    }

    public function testEncodeObjectIdentifierRejectsSingleArc(): void
    {
        $this->expectException(Exception::class);
        $this->asn1->encodeObjectIdentifier('1');
    }

    public function testEncodeObjectIdentifierRejectsNegativeArc(): void
    {
        $this->expectException(Exception::class);
        $this->asn1->encodeObjectIdentifier('1.2.-1');
    }

    public function testReadTlvRejectsEmptyData(): void
    {
        $this->expectException(Exception::class);
        $offset = 0;
        $this->asn1->readTlv('', $offset);
    }

    public function testReadTlvRejectsMissingLength(): void
    {
        $this->expectException(Exception::class);
        $offset = 0;
        $this->asn1->readTlv("\x30", $offset);
    }

    public function testReadTlvRejectsUnsupportedLongFormLength(): void
    {
        $this->expectException(Exception::class);
        $offset = 0;
        // 0x85 announces a 5-octet length, which exceeds the supported 4 octets.
        $this->asn1->readTlv("\x04\x85\x00\x00\x00\x00\x00", $offset);
    }

    public function testReadTlvHandlesLongFormLength(): void
    {
        // A 200-byte payload forces a multi-octet (long-form) DER length.
        $payload = \str_repeat("\x41", 200);
        $der = $this->asn1->encodeOctetString($payload);
        $offset = 0;
        $tlv = $this->asn1->readTlv($der, $offset);
        $this->assertSame(0x04, $tlv['tag']);
        $this->assertSame($payload, $tlv['value']);
        $this->assertSame(\strlen($der), $offset);
    }

    /**
     * OIDs whose first two arcs need more than one subidentifier octet, or that
     * are outside the range X.690 section 8.19.4 allows.
     *
     * @return array<string, array{string, string|null}>
     */
    public static function objectIdentifierProvider(): array
    {
        return [
            // [dotted OID, expected DER hex, or null when it must be rejected]
            'contentType' => ['1.2.840.113549.1.9.3', '06092a864886f70d010903'],
            'sha256' => ['2.16.840.1.101.3.4.2.1', '0609608648016503040201'],
            'minimal' => ['0.0', '060100'],
            'root 1 arc 39' => ['1.39', '06014f'],
            // 40*2 + 48 = 128, the first value needing two subidentifier octets
            'two-octet first subidentifier' => ['2.48.1', '0603810001'],
            'large second arc' => ['2.100.3', '0603813403'],
            'joint-iso-itu-t 999' => ['2.999.1', '0603883701'],
            'root arc too large' => ['3.1.2', null],
            'second arc over 39 under root 0' => ['0.100', null],
            'second arc over 39 under root 1' => ['1.50.1', null],
            'non-numeric' => ['abc.def', null],
            'negative arc' => ['1.2.-1', null],
            'single arc' => ['1', null],
            'empty arc' => ['1..2', null],
            'leading zero arc' => ['1.02', null],
            // Wider than PHP_INT_MAX, so the cast would silently saturate.
            'arc out of integer range' => ['1.2.99999999999999999999999', null],
        ];
    }

    #[DataProvider('objectIdentifierProvider')]
    public function testEncodeObjectIdentifierEdgeCases(string $oid, ?string $expectedHex): void
    {
        if ($expectedHex === null) {
            $this->expectException(Exception::class);
            $this->asn1->encodeObjectIdentifier($oid);
            return;
        }

        $this->assertSame($expectedHex, \bin2hex($this->asn1->encodeObjectIdentifier($oid)));
    }

    public function testEncodeObjectIdentifierRoundTripsThroughAnIndependentDecoder(): void
    {
        // An independent decoder reads back the same OID, which checks the
        // first-subidentifier encoding of X.690 section 8.19.4.
        foreach (['1.2.840.113549.1.9.3', '2.48.1', '2.100.3', '2.999.1', '1.39'] as $oid) {
            $der = $this->asn1->encodeObjectIdentifier($oid);
            $offset = 0;
            $tlv = $this->asn1->readTlv($der, $offset);
            $this->assertSame(0x06, $tlv['tag']);
            $this->assertSame(\strlen($der), $offset);
            $this->assertSame($oid, $this->decodeOid($tlv['value']), 'round trip failed for ' . $oid);
        }
    }

    /**
     * @return array<string, array{int}>
     */
    public static function wideIntegerProvider(): array
    {
        // 2^53 is where an int stepped by float division stops being exact, so the
        // encoders shift rather than divide.
        return [
            'below the float mantissa' => [9_007_199_254_740_991],
            'at the float mantissa' => [9_007_199_254_740_992],
            'above the float mantissa' => [9_007_199_254_740_993],
            // A power of two is exact as a double, so the wide entries here are ones
            // whose low bits do not round-trip through one.
            'alternating bits' => [6_148_914_691_236_517_205],
            'PHP_INT_MAX' => [PHP_INT_MAX],
        ];
    }

    #[DataProvider('wideIntegerProvider')]
    public function testEncodeIntegerRoundTripsWideValues(int $value): void
    {
        $offset = 0;
        $tlv = $this->asn1->readTlv($this->asn1->encodeInteger($value), $offset);

        $this->assertSame(0x02, $tlv['tag']);
        $this->assertSame($value, $this->asn1->decodeInteger($tlv['value']));
    }

    #[DataProvider('wideIntegerProvider')]
    public function testEncodeIntegerMatchesTheMagnitudeEncoder(int $value): void
    {
        // encodeIntegerBytes() steps over octets rather than arithmetic, so it is
        // the independent answer for the same value.
        $this->assertSame(
            $this->asn1->encodeIntegerBytes(\ltrim(\pack('J', $value), "\x00")),
            $this->asn1->encodeInteger($value),
        );
    }

    #[DataProvider('wideIntegerProvider')]
    public function testEncodeLengthRoundTripsWideValues(int $length): void
    {
        $encoded = $this->asn1->encodeLength($length);
        $octets = \substr($encoded, 1);

        // The octets are checked directly, no buffer this large being allocatable to
        // read them through readTlv().
        $this->assertSame(0x80 | \strlen($octets), \ord($encoded[0]));
        $this->assertSame($length, \hexdec(\bin2hex($octets)), 'wrong octets for ' . $length);
    }

    #[DataProvider('wideIntegerProvider')]
    public function testEncodeBase128IntRoundTripsWideValues(int $value): void
    {
        $oid = '1.2.' . $value;
        $der = $this->asn1->encodeObjectIdentifier($oid);

        $offset = 0;
        $this->assertSame($oid, $this->decodeOid($this->asn1->readTlv($der, $offset)['value']));
    }

    public function testEncodeObjectIdentifierRejectsASecondArcThatOverflowsTheFirstSubidentifier(): void
    {
        // X.690 section 8.19.4 combines the first two arcs into 40 * root + second,
        // which would overflow to a float here and reach encodeBase128Int() as a
        // TypeError rather than an Exception.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/OID second arc out of range/');
        $this->asn1->encodeObjectIdentifier('2.' . PHP_INT_MAX);
    }

    public function testEncodeIntegerRejectsNegative(): void
    {
        $this->expectException(Exception::class);
        $this->asn1->encodeInteger(-5);
    }

    public function testEncodeBase128IntRejectsNegative(): void
    {
        $this->expectException(Exception::class);
        $this->asn1->encodeBase128Int(-1);
    }

    /**
     * @return list<array{int}>
     */
    public static function invalidContextTagProvider(): array
    {
        return [[-1], [31], [32], [255]];
    }

    #[DataProvider('invalidContextTagProvider')]
    public function testEncodeContextRejectsOutOfRangeTagNumber(int $number): void
    {
        $this->expectException(Exception::class);
        $this->asn1->encodeContext($number, 'x');
    }

    public function testReadTlvRejectsHighTagNumberForm(): void
    {
        // X.690 section 8.1.2.4: the multi-octet tag form is not supported, its
        // continuation octet being otherwise read as a length.
        $this->expectException(Exception::class);
        $offset = 0;
        $this->asn1->readTlv("\x1f\x81\x01\x02AB", $offset);
    }

    public function testReadLengthRejectsNonMinimalLongForm(): void
    {
        // DER requires the short form for a length below 128 (X.690 section 10.1).
        $this->expectException(Exception::class);
        $offset = 0;
        $this->asn1->readTlv("\x04\x81\x02AB", $offset);
    }

    public function testReadLengthRejectsLeadingZeroOctet(): void
    {
        $this->expectException(Exception::class);
        $offset = 0;
        $this->asn1->readTlv("\x04\x82\x00\x80" . \str_repeat('A', 128), $offset);
    }

    public function testReadLengthRejectsIndefiniteForm(): void
    {
        $this->expectException(Exception::class);
        $offset = 0;
        $this->asn1->readTlv("\x30\x80\x00\x00", $offset);
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function integerProvider(): array
    {
        return [
            'zero' => ["\x00", 0],
            'one' => ["\x01", 1],
            'max byte' => ["\x7F", 127],
            'positive with pad' => ["\x00\x80", 128],
            'minus one' => ["\xFF", -1],
            'minus 128' => ["\x80", -128],
            'minus 129' => ["\xFF\x7F", -129],
        ];
    }

    #[DataProvider('integerProvider')]
    public function testDecodeIntegerHonoursTheSignBit(string $content, int $expected): void
    {
        $this->assertSame($expected, $this->asn1->decodeInteger($content));
    }

    public function testDecodeIntegerRejectsOversizedValue(): void
    {
        // A value too wide for a PHP integer is refused rather than promoted to a
        // float, which an int-typed method would report as a TypeError.
        $this->expectException(Exception::class);
        $this->asn1->decodeInteger(\str_repeat("\x7F", 16));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonMinimalIntegerProvider(): array
    {
        return [
            'redundant zero' => ["\x00\x01"],
            'redundant ff' => ["\xFF\x80"],
        ];
    }

    #[DataProvider('nonMinimalIntegerProvider')]
    public function testDecodeIntegerRejectsNonMinimalEncoding(string $content): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeInteger($content);
    }

    public function testDecodeGeneralizedTime(): void
    {
        $this->assertSame(1_700_000_000, $this->asn1->decodeGeneralizedTime('20231114221320Z'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidGeneralizedTimeProvider(): array
    {
        return [
            'empty' => [''],
            'no zone' => ['20231114221320'],
            'local zone' => ['20231114221320+0100'],
            'no seconds' => ['202311142213Z'],
            'fractional' => ['20231114221320.5Z'],
            'not a number' => ['yyyyMMddHHmmssZ'],
        ];
    }

    #[DataProvider('invalidGeneralizedTimeProvider')]
    public function testDecodeGeneralizedTimeRejectsNonDerForms(string $value): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeGeneralizedTime($value);
    }

    /**
     * @return list<array{string}>
     */
    public static function outOfRangeGeneralizedTimeProvider(): array
    {
        return [
            ['20261332255959Z'], // month 13, day 32, hour 25
            ['20260000000000Z'], // month 0, day 0
            ['20269999999999Z'], // every field out of range
            ['20260229120000Z'], // 29 February in a common year
            ['20260431000000Z'], // 31 April
            ['20260101006000Z'], // second 60
        ];
    }

    /**
     * gmmktime() wraps an out-of-range field instead of failing, so without a
     * range check a nextUpdate of 20219999999999Z would decode to 2029 and carry
     * an expired OCSP response past its validity check.
     */
    #[DataProvider('outOfRangeGeneralizedTimeProvider')]
    public function testDecodeGeneralizedTimeRejectsOutOfRangeFields(string $value): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Out-of-range/');
        $this->asn1->decodeGeneralizedTime($value);
    }

    public function testDecodeGeneralizedTimeAcceptsALegitimateLeapDay(): void
    {
        $this->assertSame(\gmmktime(12, 0, 0, 2, 29, 2028), $this->asn1->decodeGeneralizedTime('20280229120000Z'));
    }

    /**
     * Fraction-of-second forms, and what each is worth as a Unix time.
     *
     * @return array<string, array{string}>
     */
    public static function fractionalGeneralizedTimeProvider(): array
    {
        return [
            'one digit' => ['20231114221320.5Z'],
            'three digits' => ['20231114221320.123Z'],
            'ending in a non-zero digit' => ['20231114221320.001Z'],
        ];
    }

    /**
     * RFC 3161 section 2.4.2 lifts the one-second granularity RFC 5280 section
     * 4.1.2.5.2 imposes, for a timestamp token's genTime. The fraction cannot be
     * carried in a Unix time, so it is dropped once validated.
     */
    #[DataProvider('fractionalGeneralizedTimeProvider')]
    public function testDecodeGeneralizedTimeAcceptsAFractionWhenAsked(string $value): void
    {
        $this->assertSame(1_700_000_000, $this->asn1->decodeGeneralizedTime($value, true));
    }

    #[DataProvider('fractionalGeneralizedTimeProvider')]
    public function testDecodeGeneralizedTimeRefusesAFractionByDefault(string $value): void
    {
        // RFC 5280 and RFC 6960 hold every other field this codec reads to whole
        // seconds, so the fraction is admitted only where the caller opts in.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid ASN.1 GeneralizedTime/');
        $this->asn1->decodeGeneralizedTime($value);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedFractionProvider(): array
    {
        return [
            // X.690 section 11.7: the fraction omits all trailing zeros, and is
            // omitted entirely when it would be zero.
            'trailing zero' => ['20231114221320.10Z'],
            'zero fraction' => ['20231114221320.0Z'],
            'point with no digits' => ['20231114221320.Z'],
            'point but no zone' => ['20231114221320.5'],
            'non-digit fraction' => ['20231114221320.xZ'],
            'out-of-range field under a fraction' => ['20261332255959.5Z'],
        ];
    }

    #[DataProvider('malformedFractionProvider')]
    public function testDecodeGeneralizedTimeRejectsAMalformedFraction(string $value): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeGeneralizedTime($value, true);
    }

    /**
     * @return list<array{string, int}>
     */
    public static function utcTimeProvider(): array
    {
        // RFC 5280 section 4.1.2.5.1: YY >= 50 is 19YY, below it is 20YY.
        return [
            ['260824120000Z', 1_787_572_800],
            ['500101000000Z', -631_152_000],
            ['491231235959Z', 2_524_607_999],
        ];
    }

    #[DataProvider('utcTimeProvider')]
    public function testDecodeUtcTime(string $value, int $expected): void
    {
        $this->assertSame($expected, $this->asn1->decodeUtcTime($value));
    }

    /**
     * @return list<array{string}>
     */
    public static function invalidUtcTimeProvider(): array
    {
        return [
            ['2608241200Z'], // no seconds
            ['260824120000'], // no zone
            ['260824120000+0100'], // offset zone
            ['261324120000Z'], // month 13
            [''],
        ];
    }

    #[DataProvider('invalidUtcTimeProvider')]
    public function testDecodeUtcTimeRejectsNonDerForms(string $value): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeUtcTime($value);
    }

    public function testDecodeTimeAcceptsBothChoiceAlternatives(): void
    {
        $utc = ['tag' => 0x17, 'value' => '260824120000Z', 'raw' => ''];
        $generalized = ['tag' => 0x18, 'value' => '20260824120000Z', 'raw' => ''];

        $this->assertSame(1_787_572_800, $this->asn1->decodeTime($utc));
        $this->assertSame(1_787_572_800, $this->asn1->decodeTime($generalized));
    }

    public function testDecodeTimeRejectsAnotherTag(): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeTime(['tag' => 0x04, 'value' => '20260824120000Z', 'raw' => '']);
    }

    /**
     * @return list<array{string}>
     */
    public static function decodableObjectIdentifierProvider(): array
    {
        return [
            ['1.2.840.113549.1.7.2'],
            ['2.16.840.1.101.3.4.2.1'],
            ['1.3.6.1.5.5.7.48.1.1'],
            ['0.9.2342.19200300.100.1.25'],
            ['2.999.1'],
            ['0.0'],
            ['1.39'],
        ];
    }

    /**
     * decodeObjectIdentifier() is the inverse of encodeObjectIdentifier(), checked
     * against the independent decoder below rather than against itself.
     */
    #[DataProvider('decodableObjectIdentifierProvider')]
    public function testDecodeObjectIdentifierInvertsTheEncoder(string $oid): void
    {
        $offset = 0;
        $content = $this->asn1->readTlv($this->asn1->encodeObjectIdentifier($oid), $offset)['value'];

        $this->assertSame($oid, $this->asn1->decodeObjectIdentifier($content));
        $this->assertSame($this->decodeOid($content), $this->asn1->decodeObjectIdentifier($content));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidObjectIdentifierProvider(): array
    {
        return [
            'empty' => [''],
            'leading 0x80 in the first subidentifier' => ["\x80\x01"],
            'leading 0x80 in a later subidentifier' => ["\x2A\x80\x01"],
            'truncated continuation' => ["\x2A\x86"],
        ];
    }

    #[DataProvider('invalidObjectIdentifierProvider')]
    public function testDecodeObjectIdentifierRejectsMalformedContent(string $content): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeObjectIdentifier($content);
    }

    public function testDecodeObjectIdentifierRejectsAnArcWiderThanAnInteger(): void
    {
        // Ten continuation octets carry 70 bits, more than a PHP integer holds.
        $content = "\x2A" . \str_repeat("\xFF", 10) . "\x01";

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/arc out of range/');
        $this->asn1->decodeObjectIdentifier($content);
    }

    public function testEncodeLengthRejectsANegativeLength(): void
    {
        // The method is public and PHP does not enforce the int<0, max> docblock
        // type, so a negative length is refused rather than emitted as 0xFF.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Negative ASN.1 length/');
        $this->asn1->encodeLength(-1);
    }

    public function testDecodeBitString(): void
    {
        $offset = 0;
        $element = $this->asn1->readTlv("\x03\x04\x00abc", $offset);
        $this->assertSame('abc', $this->asn1->decodeBitString($element));
    }

    /**
     * @return array<string, array{array{tag: int, value: string, raw: string}}>
     */
    public static function invalidBitStringProvider(): array
    {
        return [
            'wrong tag' => [['tag' => 0x04, 'value' => "\x00a", 'raw' => '']],
            'empty' => [['tag' => 0x03, 'value' => '', 'raw' => '']],
            'unused bits' => [['tag' => 0x03, 'value' => "\x03a", 'raw' => '']],
        ];
    }

    /**
     * @param array{tag: int, value: string, raw: string} $element
     */
    #[DataProvider('invalidBitStringProvider')]
    public function testDecodeBitStringRejectsMalformedValues(array $element): void
    {
        $this->expectException(Exception::class);
        $this->asn1->decodeBitString($element);
    }

    public function testAssertSingleElement(): void
    {
        $this->asn1->assertSingleElement($this->asn1->encodeSequence('x'), 0x30, 'thing');
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function invalidSingleElementProvider(): array
    {
        return [
            'empty' => ['', 0x30],
            'trailing bytes' => ["\x30\x01x\x00", 0x30],
            'wrong tag' => ["\x31\x01x", 0x30],
            'truncated' => ["\x30\x05x", 0x30],
        ];
    }

    #[DataProvider('invalidSingleElementProvider')]
    public function testAssertSingleElementRejectsAnythingElse(string $value, int $tag): void
    {
        $this->expectException(Exception::class);
        $this->asn1->assertSingleElement($value, $tag, 'thing');
    }

    /**
     * Decode OID content octets back to dotted form.
     *
     * Written by hand so that encodeObjectIdentifier() and decodeObjectIdentifier()
     * are checked against something other than each other.
     */
    private function decodeOid(string $content): string
    {
        $value = 0;
        $arcs = [];
        $length = \strlen($content);
        for ($idx = 0; $idx < $length; ++$idx) {
            $byte = \ord($content[$idx]);
            $value = ($value << 7) | ($byte & 0x7F);
            if (($byte & 0x80) !== 0) {
                continue;
            }

            if ($arcs === []) {
                $root = \min(2, \intdiv($value, 40));
                $arcs[] = (string) $root;
                $arcs[] = (string) ($value - (40 * $root));
            } else {
                $arcs[] = (string) $value;
            }

            $value = 0;
        }

        return \implode('.', $arcs);
    }

    public function testDecodeExtensionsReadsCriticalityAndValue(): void
    {
        $extensions = $this->asn1->encodeSequence(
            $this->extension('2.5.29.20', $this->asn1->encodeInteger(7))
                . $this->extension('2.5.29.28', $this->asn1->encodeSequence(''), true),
        );

        $this->assertSame(
            [
                '2.5.29.20' => ['critical' => false, 'value' => $this->asn1->encodeInteger(7)],
                '2.5.29.28' => ['critical' => true, 'value' => $this->asn1->encodeSequence('')],
            ],
            $this->asn1->decodeExtensions($extensions, 'CRL extension'),
        );
    }

    public function testDecodeExtensionsTreatsAnAbsentFieldAsEmpty(): void
    {
        $this->assertSame([], $this->asn1->decodeExtensions('', 'CRL extension'));
    }

    public function testDecodeExtensionsRefusesASecondExtensionsSequence(): void
    {
        // Every caller hands over the content octets of an EXPLICIT context wrapper,
        // which holds one element and nothing else, so a second SEQUENCE is refused
        // rather than left unread.
        $hidden = $this->asn1->encodeSequence($this->extension('2.5.29.27', $this->asn1->encodeInteger(1), true));
        $visible = $this->asn1->encodeSequence($this->extension('2.5.29.20', $this->asn1->encodeInteger(7)));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the CRL extensions/');
        $this->asn1->decodeExtensions($visible . $hidden, 'CRL extension');
    }

    public function testDecodeExtensionsRefusesBytesAfterTheSequence(): void
    {
        $extensions = $this->asn1->encodeSequence($this->extension('2.5.29.20', $this->asn1->encodeInteger(7)));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the CRL extensions/');
        $this->asn1->decodeExtensions($extensions . 'xyz', 'CRL extension');
    }

    public function testDecodeExtensionsAcceptsAnExplicitFalseCriticalFlag(): void
    {
        $extension = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('2.5.29.20') . $this->asn1->encodeBoolean(false)
                . $this->asn1->encodeOctetString($this->asn1->encodeInteger(7)),
        );

        $this->assertSame(
            ['2.5.29.20' => ['critical' => false, 'value' => $this->asn1->encodeInteger(7)]],
            $this->asn1->decodeExtensions($this->asn1->encodeSequence($extension), 'CRL extension'),
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedCriticalFlagProvider(): array
    {
        return [
            'a zero-length BOOLEAN' => ["\x01\x00"],
            'a two-octet BOOLEAN' => ["\x01\x02\x00\x00"],
            'an eight-octet BOOLEAN' => ["\x01\x08" . \str_repeat("\xFF", 8)],
        ];
    }

    #[DataProvider('malformedCriticalFlagProvider')]
    public function testDecodeExtensionsRejectsACriticalFlagThatIsNotOneOctet(string $flag): void
    {
        // X.690 section 8.2.1: a BOOLEAN carries exactly one content octet, so any
        // other length is refused.
        $extension = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('2.5.29.20') . $flag
                . $this->asn1->encodeOctetString($this->asn1->encodeInteger(7)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid CRL extension critical flag/');
        $this->asn1->decodeExtensions($this->asn1->encodeSequence($extension), 'CRL extension');
    }

    public function testDecodeExtensionsAcceptsANonCanonicalTrueCriticalFlag(): void
    {
        // DER fixes TRUE at 0xFF, but encoders in the wild emit 0x01, so any
        // non-zero octet reads as TRUE.
        $extension = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('2.5.29.20') . "\x01\x01\x01"
                . $this->asn1->encodeOctetString($this->asn1->encodeInteger(7)),
        );

        $this->assertSame(
            ['2.5.29.20' => ['critical' => true, 'value' => $this->asn1->encodeInteger(7)]],
            $this->asn1->decodeExtensions($this->asn1->encodeSequence($extension), 'CRL extension'),
        );
    }

    public function testDecodeExtensionsRejectsTrailingBytesInsideAnExtension(): void
    {
        // extnValue is the last field, so nothing may follow it.
        $extension = $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier('2.5.29.20')
                . $this->asn1->encodeOctetString($this->asn1->encodeInteger(7))
                . $this->asn1->encodeInteger(9),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes in CRL extension/');
        $this->asn1->decodeExtensions($this->asn1->encodeSequence($extension), 'CRL extension');
    }

    public function testReadLengthAcceptsAFourOctetLongForm(): void
    {
        // The octet count is not capped below the DER maximum of four, which on a
        // 32-bit build would refuse every element above 16 MiB.
        $offset = 0;
        $this->assertSame(0x0100_0000, $this->asn1->readLength("\x84\x01\x00\x00\x00", $offset));
        $this->assertSame(5, $offset);
    }

    public function testReadLengthRejectsALongFormOverFourOctets(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported ASN.1 length/');
        $offset = 0;
        $this->asn1->readLength("\x85\x01\x00\x00\x00\x00", $offset);
    }

    public function testDecodeExtensionsRejectsADuplicateOid(): void
    {
        // RFC 5280 sections 4.2 and 5.2 admit one instance of each type, so a
        // duplicate is refused rather than collapsed to the last.
        $extensions = $this->asn1->encodeSequence(
            $this->extension('2.5.29.28', $this->asn1->encodeSequence("\x81\x01\xFF"), true)
                . $this->extension('2.5.29.28', $this->asn1->encodeSequence('')),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Duplicate CRL extension: 2\.5\.29\.28/');
        $this->asn1->decodeExtensions($extensions, 'CRL extension');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedExtensionsProvider(): array
    {
        $asn1 = new Asn1();

        return [
            'not a SEQUENCE' => [$asn1->encodeSet('')],
            'a member that is not a SEQUENCE' => [$asn1->encodeSequence($asn1->encodeInteger(1))],
            'a member whose first field is not an OID' => [
                $asn1->encodeSequence($asn1->encodeSequence($asn1->encodeInteger(1) . $asn1->encodeOctetString(''))),
            ],
            'a member whose value is not an OCTET STRING' => [
                $asn1->encodeSequence($asn1->encodeSequence(
                    $asn1->encodeObjectIdentifier('2.5.29.20') . $asn1->encodeInteger(1),
                )),
            ],
        ];
    }

    #[DataProvider('malformedExtensionsProvider')]
    public function testDecodeExtensionsRejectsMalformedStructures(string $extensions): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid CRL extension/');
        $this->asn1->decodeExtensions($extensions, 'CRL extension');
    }

    public function testReadOptionalTlvReadsAnElementAndAdvances(): void
    {
        $data = $this->asn1->encodeInteger(7) . $this->asn1->encodeNull();

        $offset = 0;
        $first = $this->asn1->readOptionalTlv($data, $offset);
        $this->assertNotNull($first);
        $this->assertSame(0x02, $first['tag']);
        $this->assertSame(3, $offset);

        $second = $this->asn1->readOptionalTlv($data, $offset);
        $this->assertNotNull($second);
        $this->assertSame(0x05, $second['tag']);
        $this->assertSame(5, $offset);
    }

    public function testReadOptionalTlvAnswersNullAtTheEndWithoutMovingTheCursor(): void
    {
        $data = $this->asn1->encodeNull();

        $offset = \strlen($data);
        $this->assertNull($this->asn1->readOptionalTlv($data, $offset));
        $this->assertSame(\strlen($data), $offset);

        $empty = 0;
        $this->assertNull($this->asn1->readOptionalTlv('', $empty));
        $this->assertSame(0, $empty);
    }

    public function testDecodeAlgorithmIdentifierReadsTheOidWithAbsentOrNullParameters(): void
    {
        $oid = '2.16.840.1.101.3.4.2.1';

        $this->assertSame($oid, $this->asn1->decodeAlgorithmIdentifier(
            $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($oid)),
            'digest',
        ));

        $this->assertSame($oid, $this->asn1->decodeAlgorithmIdentifier(
            $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier($oid) . $this->asn1->encodeNull()),
            'digest',
        ));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function malformedAlgorithmIdentifierProvider(): array
    {
        $asn1 = new Asn1();
        $oid = $asn1->encodeObjectIdentifier('2.16.840.1.101.3.4.2.1');
        $identifier = $asn1->encodeSequence($oid . $asn1->encodeNull());

        return [
            // parameters is the one field that may follow the OID, and it has to be
            // absent or NULL, so nothing else is left unread.
            'a second element after the parameters' => [
                $asn1->encodeSequence($oid . $asn1->encodeNull() . $asn1->encodeOctetString('chosen')),
                'Trailing bytes in the digest AlgorithmIdentifier',
            ],
            'parameters that are neither absent nor NULL' => [
                $asn1->encodeSequence($oid . $asn1->encodeOctetString('chosen')),
                'Unsupported digest AlgorithmIdentifier parameters',
            ],
            'not a SEQUENCE' => [$asn1->encodeSet($oid), 'Invalid digest AlgorithmIdentifier'],
            'trailing bytes after the identifier' => [
                $identifier . $asn1->encodeNull(),
                'Invalid digest AlgorithmIdentifier',
            ],
            'first field is not an OID' => [
                $asn1->encodeSequence($asn1->encodeOctetString('chosen')),
                'Invalid digest AlgorithmIdentifier',
            ],
            'empty' => [$asn1->encodeSequence(''), 'Malformed ASN.1 structure'],
        ];
    }

    #[DataProvider('malformedAlgorithmIdentifierProvider')]
    public function testDecodeAlgorithmIdentifierRejectsWhatItCannotWeigh(string $der, string $message): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/^' . \preg_quote($message, '/') . '/');
        $this->asn1->decodeAlgorithmIdentifier($der, 'digest');
    }

    /**
     * Encode one X.509 Extension.
     */
    private function extension(string $oid, string $value, bool $critical = false): string
    {
        return $this->asn1->encodeSequence(
            $this->asn1->encodeObjectIdentifier($oid) . ($critical ? $this->asn1->encodeBoolean(true) : '')
                . $this->asn1->encodeOctetString($value),
        );
    }

    // Asn1::encodeLength() throws on a length needing more than 127 octets to
    // represent, which requires content larger than 2^1016 bytes and so cannot be
    // exercised in a unit test.
}
