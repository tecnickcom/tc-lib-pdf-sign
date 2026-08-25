<?php

declare(strict_types=1);

/**
 * DssTest.php
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
use Com\Tecnick\Pdf\Sign\Output\Dss;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * DSS Output Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Dss::class)]
final class DssTest extends TestCase
{
    private Dss $dss;

    protected function setUp(): void
    {
        $this->dss = new Dss();
    }

    public function testEmitReturnsNothingForEmptyMaterial(): void
    {
        $pon = 7;
        $result = $this->dss->emit(['certs' => [], 'ocsp' => [], 'crls' => []], 'SIG', $pon);
        $this->assertSame([], $result['objects']);
        $this->assertSame(0, $result['object_id']);
        $this->assertSame(7, $pon);
    }

    public function testEmitProducesStreamsVriAndDss(): void
    {
        $pon = 10;
        $contents = 'CMS-SIGNATURE-BYTES';
        $result = $this->dss->emit(
            ['certs' => ['CERT-DER'], 'ocsp' => ['OCSP-RESP'], 'crls' => ['CRL-DATA']],
            $contents,
            $pon,
        );

        // 3 streams (11,12,13), VRI (14), DSS (15).
        $this->assertSame(15, $pon);
        $this->assertSame(15, $result['object_id']);

        // The whole map is keyed by object number, ready for an incremental xref.
        $vriKey = \strtoupper(\sha1($contents));
        $this->assertSame(
            [
                11 => "11 0 obj\n<< /Length 8 >>\nstream\nCERT-DER\nendstream\nendobj\n",
                12 => "12 0 obj\n<< /Length 9 >>\nstream\nOCSP-RESP\nendstream\nendobj\n",
                13 => "13 0 obj\n<< /Length 8 >>\nstream\nCRL-DATA\nendstream\nendobj\n",
                14 => "14 0 obj\n<< /Type /VRI /Cert [ 11 0 R ] /OCSP [ 12 0 R ] /CRL [ 13 0 R ] >>\nendobj\n",
                15 =>
                    "15 0 obj\n<< /Type /DSS /VRI << /"
                        . $vriKey
                        . ' 14 0 R >>'
                        . ' /Certs [ 11 0 R ] /OCSPs [ 12 0 R ] /CRLs [ 13 0 R ]'
                        . " >>\nendobj\n",
            ],
            $result['objects'],
        );
    }

    /**
     * @return array<string, array{array{certs: list<string>, ocsp: list<string>, crls: list<string>}}>
     */
    public static function materialWithAnEmptyPayloadProvider(): array
    {
        return [
            'empty certificate' => [['certs' => ['CERT-DER', ''], 'ocsp' => [], 'crls' => []]],
            'empty OCSP response' => [['certs' => [], 'ocsp' => [''], 'crls' => []]],
            'empty CRL' => [['certs' => [], 'ocsp' => [], 'crls' => ['CRL-DATA', '']]],
        ];
    }

    /**
     * @param array{certs: list<string>, ocsp: list<string>, crls: list<string>} $material
     */
    #[DataProvider('materialWithAnEmptyPayloadProvider')]
    public function testEmitRejectsAnEmptyPayload(array $material): void
    {
        // A /Certs or /OCSPs array pointing at a zero-length stream is validation
        // material no validator can use, so an empty payload is refused.
        $pon = 10;

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Empty Document Security Store payload/');
        $this->dss->emit($material, 'SIG', $pon);
    }

    /**
     * Material a store could hand back, with the shape the docblock declares and
     * another type inside it.
     *
     * Typed loosely for the reason invalidStateProvider() is: the point of the check
     * is material whose members are not what the declared shape promises.
     *
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidMaterialProvider(): array
    {
        return [
            'a payload that is an integer' => [
                ['certs' => [42], 'ocsp' => [], 'crls' => []],
                'Invalid Document Security Store payload: int',
            ],
            'a payload that is null' => [
                ['certs' => [], 'ocsp' => [null], 'crls' => []],
                'Invalid Document Security Store payload: null',
            ],
            'a payload that is an array' => [
                ['certs' => [], 'ocsp' => [], 'crls' => [['x']]],
                'Invalid Document Security Store payload: array',
            ],
            'a field that is not an array' => [
                ['certs' => 'CERT-DER', 'ocsp' => [], 'crls' => []],
                'Invalid DSS material field: certs',
            ],
            'a field the store lost' => [
                ['certs' => ['CERT-DER'], 'crls' => []],
                'Invalid DSS material field: ocsp',
            ],
        ];
    }

    /**
     * @param array{certs: list<string>, ocsp: list<string>, crls: list<string>} $material
     */
    #[DataProvider('invalidMaterialProvider')]
    public function testEmitRejectsMaterialThatIsNotAListOfPayloads(array $material, string $message): void
    {
        // The material crosses the host's store between the collection pass and the
        // incremental update that writes it, as the carried state does. A missing
        // field would reach count() as null and a payload that is not a string would
        // reach hash(), both as a TypeError.
        $pon = 10;

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $this->dss->emit($material, 'SIG', $pon);
    }

    public function testEmitLeavesTheObjectNumberAloneWhenAPayloadIsEmpty(): void
    {
        $pon = 10;

        try {
            $this->dss->emit(['certs' => ['CERT-DER', ''], 'ocsp' => [], 'crls' => []], 'SIG', $pon);
        } catch (Exception) {
            // The bound is what is asserted, not the message.
        }

        $this->assertSame(10, $pon);
    }

    public function testEmitOmitsEmptyCategories(): void
    {
        $pon = 0;
        $result = $this->dss->emit(['certs' => ['A', 'B'], 'ocsp' => [], 'crls' => []], 'SIG', $pon);

        // 2 cert streams (1,2), VRI (3), DSS (4).
        $this->assertSame(4, $result['object_id']);
        $objects = \implode('', $result['objects']);

        $this->assertStringContainsString('<< /Type /VRI /Cert [ 1 0 R 2 0 R ] >>', $objects);
        $this->assertStringNotContainsString('/OCSP ', $objects);
        $this->assertStringNotContainsString('/CRL ', $objects);
        $this->assertStringContainsString('/Certs [ 1 0 R 2 0 R ]', $objects);
        $this->assertStringNotContainsString('/OCSPs', $objects);
        $this->assertStringNotContainsString('/CRLs', $objects);
    }

    public function testEmitEncryptsStreams(): void
    {
        $pon = 0;
        $encryptor = static fn(string $data, int $objectId): string => 'E' . $objectId . ':' . $data;
        $result = $this->dss->emit(['certs' => ['X'], 'ocsp' => [], 'crls' => []], 'SIG', $pon, $encryptor);

        // Stream 1 carries the encrypted payload "E1:X" (length 4).
        $objects = \implode('', $result['objects']);
        $this->assertStringContainsString("1 0 obj\n<< /Length 4 >>\nstream\nE1:X\nendstream\nendobj\n", $objects);
    }

    public function testEmitRejectsNonStringEncryptorResult(): void
    {
        $pon = 0;
        $encryptor = static fn(string $_data, int $objectId): int => $objectId;
        $this->expectException(Exception::class);
        $this->dss->emit(['certs' => ['X'], 'ocsp' => [], 'crls' => []], 'SIG', $pon, $encryptor);
    }

    public function testEmitLeavesTheObjectNumberAloneWhenItFails(): void
    {
        // Numbers are assigned from a local cursor and written back only once every
        // object exists, so a failure leaves the host's counter untouched.
        $pon = 10;
        $encryptor = static fn(string $_data, int $objectId): int => $objectId;

        try {
            $this->dss->emit(['certs' => ['A', 'B', 'C'], 'ocsp' => [], 'crls' => []], 'SIG', $pon, $encryptor);
            $this->fail('Expected the encryptor result to be refused');
        } catch (Exception) {
            $this->assertSame(10, $pon);
        }
    }

    public function testEmitRejectsACarriedObjectNumberItWouldAssignAgain(): void
    {
        // This update assigns from $pon + 1 upwards, so a carried number at or beyond
        // that would collide with one of them.
        $pon = 0;
        $key = \strtoupper(\sha1('SIG'));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/would assign again from 1/');
        $this->dss->emit(['certs' => ['A'], 'ocsp' => [], 'crls' => []], 'SIG', $pon, null, [
            'vri' => [$key => 1],
            'certs' => [1],
            'ocsp' => [],
            'crls' => [],
            'objects' => [\hash('sha256', 'A') => 1],
        ]);
    }

    public function testEmitAcceptsACarriedStateBelowTheObjectNumber(): void
    {
        $pon = 5;
        $key = \strtoupper(\sha1('OLD'));

        $result = $this->dss->emit(['certs' => ['A'], 'ocsp' => [], 'crls' => []], 'SIG', $pon, null, [
            'vri' => [$key => 2],
            'certs' => [2],
            'ocsp' => [],
            'crls' => [],
            'objects' => [],
        ]);

        $this->assertSame([2, 6], $result['state']['certs']);
        $this->assertSame(8, $pon);
    }

    public function testEmitReturnsStateForTheNextUpdate(): void
    {
        $pon = 0;
        $result = $this->dss->emit(['certs' => ['A'], 'ocsp' => ['O'], 'crls' => ['C']], 'SIG', $pon);

        $this->assertArrayHasKey('state', $result);
        $this->assertSame([1], $result['state']['certs']);
        $this->assertSame([2], $result['state']['ocsp']);
        $this->assertSame([3], $result['state']['crls']);
        $this->assertSame([\strtoupper(\sha1('SIG')) => 4], $result['state']['vri']);
    }

    public function testEmitMergesTheEarlierVriEntries(): void
    {
        // A DSS written by an incremental update replaces the one before it, so a
        // second signature has to carry the first signature's VRI entry forward.
        $pon = 0;
        $first = $this->dss->emit(['certs' => ['A'], 'ocsp' => [], 'crls' => []], 'SIG-1', $pon);

        $second = $this->dss->emit(
            ['certs' => ['B'], 'ocsp' => [], 'crls' => []],
            'SIG-2',
            $pon,
            null,
            $first['state'],
        );

        $dictionary = $second['objects'][$second['object_id']] ?? '';

        $firstKey = \strtoupper(\sha1('SIG-1'));
        $secondKey = \strtoupper(\sha1('SIG-2'));
        $this->assertStringContainsString('/' . $firstKey . ' ', $dictionary);
        $this->assertStringContainsString('/' . $secondKey . ' ', $dictionary);

        // The DSS-level arrays are the union, so the earlier VRI still resolves.
        $this->assertStringContainsString('/Certs [ 1 0 R 4 0 R ]', $dictionary);
        $this->assertSame([1, 4], $second['state']['certs']);
    }

    public function testEmitCarriesStateThroughAnEmptyUpdate(): void
    {
        $pon = 0;
        $first = $this->dss->emit(['certs' => ['A'], 'ocsp' => [], 'crls' => []], 'SIG-1', $pon);

        $empty = $this->dss->emit(['certs' => [], 'ocsp' => [], 'crls' => []], 'SIG-2', $pon, null, $first['state']);

        $this->assertSame(0, $empty['object_id']);
        $this->assertSame($first['state'], $empty['state']);
    }

    public function testEmitReusesObjectsAnEarlierRevisionAlreadyWrote(): void
    {
        // Material an earlier revision already wrote is referenced again rather than
        // written a second time.
        $dss = new Dss();
        $material = ['certs' => ['CERT-A', 'CERT-B'], 'ocsp' => ['OCSP-1'], 'crls' => []];

        $pon = 10;
        $first = $dss->emit($material, 'signature-1', $pon);
        $second = $dss->emit($material, 'signature-2', $pon, null, $first['state']);

        // Only the new VRI entry and the new DSS dictionary are written.
        $this->assertCount(5, $first['objects']);
        $this->assertCount(2, $second['objects']);

        $this->assertSame($first['state']['certs'], $second['state']['certs']);
        $this->assertSame($first['state']['ocsp'], $second['state']['ocsp']);
        $this->assertCount(2, $second['state']['vri']);
    }

    public function testEmitWritesMaterialAnEarlierRevisionDidNotCarry(): void
    {
        $dss = new Dss();

        $pon = 10;
        $first = $dss->emit(['certs' => ['CERT-A'], 'ocsp' => [], 'crls' => []], 'signature-1', $pon);
        $second = $dss->emit(
            ['certs' => ['CERT-A', 'CERT-B'], 'ocsp' => [], 'crls' => []],
            'signature-2',
            $pon,
            null,
            $first['state'],
        );

        // CERT-A keeps the object the first revision gave it; CERT-B gets a new one.
        $this->assertSame([11], $first['state']['certs']);
        $this->assertSame([11, 14], $second['state']['certs']);
        $this->assertStringContainsString('CERT-B', \implode('', $second['objects']));
        $this->assertStringNotContainsString('CERT-A', \implode('', $second['objects']));
    }

    public function testEmitAcceptsAStateWithoutTheObjectsKey(): void
    {
        // State exported by an earlier version of this class.
        $dss = new Dss();
        $pon = 10;
        $result = $dss->emit(['certs' => ['CERT-A'], 'ocsp' => [], 'crls' => []], 'signature', $pon, null, [
            'vri' => [],
            'certs' => [],
            'ocsp' => [],
            'crls' => [],
        ]);

        $this->assertSame(13, $result['object_id']);
        $this->assertSame([11], $result['state']['certs']);
    }

    public function testEmitRejectsANegativeObjectNumber(): void
    {
        // Object numbers start at 1 (ISO 32000-1 section 7.5.4), so the emitter may
        // be handed 0 but never a negative number.
        $pon = -5;

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/object number/');
        (new Dss())->emit(['certs' => ['CERT'], 'ocsp' => [], 'crls' => []], 'signature', $pon);
    }

    public function testEmitRejectsEmptySignatureContents(): void
    {
        // The VRI key is the digest of the signature it indexes, so '' would yield a
        // well-formed key no signature can match.
        $pon = 1;

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/signature contents/');
        (new Dss())->emit(['certs' => ['CERT'], 'ocsp' => [], 'crls' => []], '', $pon);
    }

    public function testEmitAcceptsAZeroStartingObjectNumber(): void
    {
        $pon = 0;
        $result = (new Dss())->emit(['certs' => ['CERT'], 'ocsp' => [], 'crls' => []], 'signature', $pon);

        $this->assertSame(3, $result['object_id']);
        $this->assertSame([1], $result['state']['certs']);
    }

    /**
     * A carried state with a value that must not reach the emitted dictionary.
     *
     * Typed loosely because the point of the check is a state whose values are not
     * the ones the declared shape promises.
     *
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidStateProvider(): array
    {
        $key = \strtoupper(\sha1('signature'));

        return [
            'a VRI key that is not a digest' => [
                ['vri' => ['not a hex key' => 9], 'certs' => [], 'ocsp' => [], 'crls' => []],
                'Invalid DSS VRI key',
            ],
            'a lowercase VRI key' => [
                ['vri' => [\strtolower($key) => 9], 'certs' => [], 'ocsp' => [], 'crls' => []],
                'Invalid DSS VRI key',
            ],
            'a VRI entry pointing at object 0' => [
                ['vri' => [$key => 0], 'certs' => [], 'ocsp' => [], 'crls' => []],
                'Invalid DSS object number',
            ],
            'a negative certificate object' => [
                ['vri' => [], 'certs' => [-5], 'ocsp' => [], 'crls' => []],
                'Invalid DSS object number',
            ],
            'a negative OCSP object' => [
                ['vri' => [], 'certs' => [], 'ocsp' => [-5], 'crls' => []],
                'Invalid DSS object number',
            ],
            'a negative CRL object' => [
                ['vri' => [], 'certs' => [], 'ocsp' => [], 'crls' => [-5]],
                'Invalid DSS object number',
            ],
            // A store that stringifies numbers returns the declared shape with
            // another type in it, which strict types would report as a TypeError.
            'a certificate object as a string' => [
                ['vri' => [], 'certs' => ['3'], 'ocsp' => [], 'crls' => []],
                'Invalid DSS object number in the carried state: string',
            ],
            'a VRI entry pointing at a float' => [
                ['vri' => [$key => 3.5], 'certs' => [], 'ocsp' => [], 'crls' => []],
                'Invalid DSS object number in the carried state: float',
            ],
            'an OCSP object that is null' => [
                ['vri' => [], 'certs' => [], 'ocsp' => [null], 'crls' => []],
                'Invalid DSS object number in the carried state: null',
            ],
            // The shape is host state as much as the values are: a store that lost a
            // key, or handed one back as something other than an array, would reach a
            // spread as null.
            'a VRI map that is not an array' => [
                ['vri' => 'x', 'certs' => [], 'ocsp' => [], 'crls' => []],
                'Invalid DSS state field: vri',
            ],
            'a certificate list that is not an array' => [
                ['vri' => [], 'certs' => 'x', 'ocsp' => [], 'crls' => []],
                'Invalid DSS state field: certs',
            ],
            'an OCSP list that is not an array' => [
                ['vri' => [], 'certs' => [], 'ocsp' => 'x', 'crls' => []],
                'Invalid DSS state field: ocsp',
            ],
            'a CRL list that is not an array' => [
                ['vri' => [], 'certs' => [], 'ocsp' => [], 'crls' => 'x'],
                'Invalid DSS state field: crls',
            ],
            'an object map that is not an array' => [
                ['vri' => [], 'certs' => [], 'ocsp' => [], 'crls' => [], 'objects' => 'x'],
                'Invalid DSS state field: objects',
            ],
        ];
    }

    /**
     * Carried states that are missing a key rather than holding a wrong one.
     *
     * @return array<string, array{array<string, mixed>}>
     */
    public static function incompleteStateProvider(): array
    {
        $full = ['vri' => [], 'certs' => [], 'ocsp' => [], 'crls' => [], 'objects' => []];

        return [
            'no vri' => [\array_diff_key($full, ['vri' => 1])],
            'no certs' => [\array_diff_key($full, ['certs' => 1])],
            'no ocsp' => [\array_diff_key($full, ['ocsp' => 1])],
            'no crls' => [\array_diff_key($full, ['crls' => 1])],
            'nothing at all' => [[]],
        ];
    }

    /**
     * @param array<string, mixed> $state
     */
    #[DataProvider('incompleteStateProvider')]
    public function testEmitTreatsAMissingStateFieldAsEmpty(array $state): void
    {
        // A key the host's store did not return defaults to the empty list, rather
        // than reaching a spread as null.
        $pon = 5;

        // A state that does not hold the declared shape is the point of the test.
        // @mago-expect analysis:possibly-invalid-argument
        $result = (new Dss())->emit(['certs' => ['CERT'], 'ocsp' => [], 'crls' => []], 'signature', $pon, null, $state);

        $this->assertSame([6], $result['state']['certs']);
    }

    public function testEmitRejectsAnObjectNumberThatWouldOverflow(): void
    {
        // The cursor is stepped with ++, which past PHP_INT_MAX yields a float and
        // would reach the private emitters as a TypeError.
        $pon = PHP_INT_MAX;

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/DSS object number overflow/');
        (new Dss())->emit(['certs' => ['CERT'], 'ocsp' => ['OCSP'], 'crls' => []], 'signature', $pon);
    }

    public function testEmitReferencesAReusedObjectOnceInTheVriArrays(): void
    {
        // emitStreams() collapses two equal payloads onto one object but answers one
        // number per input item, so the reference arrays deduplicate.
        $pon = 0;
        $result = (new Dss())->emit(['certs' => ['A', 'A'], 'ocsp' => ['B', 'B'], 'crls' => []], 'signature', $pon);

        $this->assertStringContainsString('/Cert [ 1 0 R ] /OCSP [ 2 0 R ]', $result['objects'][3] ?? '');
    }

    /**
     * @param array<string, mixed> $state
     */
    #[DataProvider('invalidStateProvider')]
    public function testEmitRejectsACarriedStateItDidNotProduce(array $state, string $expected): void
    {
        // The state crosses whatever the host stores it in between two incremental
        // updates, and its keys and numbers are interpolated into PDF syntax without
        // escaping.
        $pon = 5;

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($expected, '/') . '/');
        // A state that does not hold the declared shape is the point of the test.
        // @mago-expect analysis:possibly-invalid-argument
        (new Dss())->emit(['certs' => ['CERT'], 'ocsp' => [], 'crls' => []], 'signature', $pon, null, $state);
    }

    public function testEmitRejectsACarriedObjectsMapWithANonPositiveNumber(): void
    {
        $pon = 5;
        $state = ['vri' => [], 'certs' => [], 'ocsp' => [], 'crls' => [], 'objects' => [\hash('sha256', 'CERT') => 0]];

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid DSS object number/');
        (new Dss())->emit(['certs' => ['CERT'], 'ocsp' => [], 'crls' => []], 'signature', $pon, null, $state);
    }
}
