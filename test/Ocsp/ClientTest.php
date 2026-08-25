<?php

declare(strict_types=1);

/**
 * ClientTest.php
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

namespace Test\Ocsp;

use Com\Tecnick\Pdf\Sign\Cms\Asn1;
use Com\Tecnick\Pdf\Sign\Cms\Certificate;
use Com\Tecnick\Pdf\Sign\Exception;
use Com\Tecnick\Pdf\Sign\Ocsp\Client;
use Com\Tecnick\Pdf\Sign\Ocsp\Request;
use Com\Tecnick\Pdf\Sign\RevokedException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Test\Fixture\Authority;
use Test\Fixture\Der;

/**
 * OCSP Client Test
 *
 * @since     2026-07-15
 * @category  Library
 * @package   PdfSign
 * @author    Nicola Asuni <info@tecnick.com>
 * @copyright 2026 Nicola Asuni - Tecnick.com LTD
 * @license   https://www.gnu.org/copyleft/lesser.html GNU-LGPL v3 (see LICENSE)
 * @link      https://github.com/tecnickcom/tc-lib-pdf-sign
 */
#[CoversClass(Client::class)]
#[CoversClass(Request::class)]
final class ClientTest extends TestCase
{
    /**
     * A moment inside the validity interval the fixture responses declare.
     */
    private const NOW = 1_800_000_000;

    private Asn1 $asn1;

    private Der $der;

    private Certificate $certificate;

    private string $leafPem = '';

    private string $leafDer = '';

    private string $caDer = '';

    protected function setUp(): void
    {
        $this->asn1 = new Asn1();
        $this->der = new Der($this->asn1);
        $this->certificate = new Certificate($this->asn1);
        $this->leafPem = (string) \file_get_contents(__DIR__ . '/../data/ocsp_leaf.pem');
        $this->leafDer = Certificate::pemToDer($this->leafPem);
        $this->caDer = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem'));
    }

    public function testBuildRefusesAnIssuerThatDidNotIssueTheCertificate(): void
    {
        // A CertID mixing the leaf's issuer Name with another authority's key hash
        // names a certificate nobody issued. Ltv\Crl::validate() makes the same
        // check over a CertificateList.
        $ltvLeaf = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ltv_cert.pem'));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/did not issue the certificate/');
        (new Client($this->asn1))->build($this->caDer, $ltvLeaf);
    }

    public function testBuildAcceptsAnIssuerReIssuedUnderAnotherNameEncoding(): void
    {
        // The control for the rule above: the link is established by signature and
        // not by Name, so an authority that re-issued its own certificate with its
        // Name in another string type is still recognised as the issuer.
        $reissued = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca_printable.pem'));

        $this->assertNotSame('', (new Client($this->asn1))->build($reissued, $this->leafDer)->certId);
    }

    public function testBuildProducesValidOcspRequest(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // OCSPRequest ::= SEQ { tbsRequest SEQ { requestList SEQ OF { Request SEQ { CertID SEQ } } } }
        $offset = 0;
        $ocspRequest = $this->asn1->readTlv($request->der, $offset);
        $this->assertSame(0x30, $ocspRequest['tag']);
        $this->assertSame(\strlen($request->der), $offset);

        $certId = $this->descend($ocspRequest['value'], 4); // tbsRequest, requestList, Request, CertID
        $this->assertSame(0x30, $certId['tag']);
        $this->assertSame($request->certId, $certId['raw']);

        $inner = 0;
        $algId = $this->asn1->readTlv($certId['value'], $inner);
        $nameHash = $this->asn1->readTlv($certId['value'], $inner);
        $keyHash = $this->asn1->readTlv($certId['value'], $inner);
        $serial = $this->asn1->readTlv($certId['value'], $inner);

        // RFC 6960 section 4.1.1: the name hash covers the issuer field of the
        // certificate being checked, and the key hash the issuer certificate's key.
        $issuer = $this->certificate->fields($this->caDer);
        $this->assertSame(0x04, $nameHash['tag']);
        $this->assertSame(
            \hash('sha1', $this->certificate->fields($this->leafDer)['issuer'], true),
            $nameHash['value'],
        );
        $this->assertSame(20, \strlen($nameHash['value']));
        $this->assertSame(0x04, $keyHash['tag']);
        $this->assertSame(\hash('sha1', $issuer['public_key'], true), $keyHash['value']);
        $this->assertSame(20, \strlen($keyHash['value']));

        // hashAlgorithm OID is SHA-1 (1.3.14.3.2.26).
        $algOffset = 0;
        $oid = $this->asn1->readTlv($algId['value'], $algOffset);
        $this->assertSame($this->asn1->encodeObjectIdentifier('1.3.14.3.2.26'), $oid['raw']);

        // serialNumber is the certificate's own encoding, spliced in unchanged.
        $this->assertSame(0x02, $serial['tag']);
        $this->assertSame($this->certificate->fields($this->leafDer)['serial'], $serial['raw']);
    }

    public function testSerialNumberMatchesOpenssl(): void
    {
        $parsed = \openssl_x509_parse($this->leafPem);
        if (!\is_array($parsed)) {
            $this->fail('Unable to parse leaf certificate');
        }

        $serial = $this->certificate->fields($this->leafDer)['serial'];

        $offset = 0;
        $tlv = $this->asn1->readTlv($serial, $offset);
        $this->assertSame(\strtolower($parsed['serialNumberHex']), \bin2hex($tlv['value']));
    }

    public function testNegativeSerialIsNotReEncoded(): void
    {
        // RFC 5280 section 4.1.2.2 asks that a non-conforming negative serial still
        // works, so the serial is spliced in as the certificate encodes it.
        $negativeSerial = "\x02\x02\xF3\x1A";
        $certDer = $this->certificateWithSerial($negativeSerial);

        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $certDer);

        $this->assertStringContainsString($negativeSerial, $request->certId);
        $this->assertStringNotContainsString("\x02\x03\x00\xF3\x1A", $request->certId);
    }

    public function testFetchAcceptsMatchingResponse(): void
    {
        $client = new Client($this->asn1);
        $expected = $client->build($this->caDer, $this->leafDer);
        $response = $this->der->ocspResponse($expected->certId);

        $captured = ['url' => '', 'request' => ''];
        $transport = static function (string $url, string $request) use (&$captured, $response): string {
            $captured['url'] = $url;
            $captured['request'] = $request;
            return $response;
        };

        $result = $client->fetch('http://ocsp.example.org', $this->caDer, $this->leafDer, $transport, self::NOW);

        $this->assertSame($response, $result);
        $this->assertSame('http://ocsp.example.org', $captured['url']);
        $this->assertSame($expected->der, $captured['request']);
    }

    /**
     * A genuine, signed response with unsigned bytes added at one of the layers
     * between the OCSPResponse and the BasicOCSPResponse.
     *
     * The responder's signature spans tbsResponseData alone, and parseResponse()
     * answers with the caller's own string, so every layer is bounded.
     *
     * @return array<string, array{string}>
     */
    public static function trailingOcspBytesProvider(): array
    {
        $asn1 = new Asn1();
        $der = new Der($asn1);
        $certId = (new Client($asn1))->build(Authority::ocsp()->certDer, Authority::leaf()->certDer)->certId;

        $basic = $der->basicResponse($der->responseData($der->singleResponse($certId)));
        $inner = $asn1->encodeSequence(
            $asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.1') . $asn1->encodeOctetString($basic),
        );
        $good = $der->enumerated(0);

        return [
            'after responseBytes in the OCSPResponse' => [
                $asn1->encodeSequence($good . $asn1->encodeContext(0, $inner) . $asn1->encodeInteger(1)),
            ],
            'a second responseBytes [0]' => [
                $asn1->encodeSequence($good . $asn1->encodeContext(0, $inner) . $asn1->encodeContext(0, $inner)),
            ],
            'after ResponseBytes inside the [0] wrapper' => [
                $asn1->encodeSequence($good . $asn1->encodeContext(0, $inner . $asn1->encodeInteger(1))),
            ],
            'after the octet string inside ResponseBytes' => [
                $asn1->encodeSequence(
                    $good
                        . $asn1->encodeContext(
                            0,
                            $asn1->encodeSequence(
                                $asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.1') . $asn1->encodeOctetString($basic)
                                    . $asn1->encodeInteger(1),
                            ),
                        ),
                ),
            ],
        ];
    }

    #[DataProvider('trailingOcspBytesProvider')]
    public function testParseResponseRejectsTrailingBytes(string $response): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $this->expectException(Exception::class);
        $client->parseResponse($response, $request, self::NOW);
    }

    /**
     * A genuinely signed response whose unsigned signatureAlgorithm has been rewritten.
     *
     * The field sits outside tbsResponseData, so the responder's signature does not
     * cover it. A CertificateList carries the identifier a second time inside its TBS
     * and Crl::validate() compares the two; a BasicOCSPResponse has no inner copy, so
     * this field is held to its shape on its own.
     *
     * @return array<string, array{string, string}>
     */
    public static function rewrittenSignatureAlgorithmProvider(): array
    {
        $asn1 = new Asn1();
        $oid = $asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID);
        $chosen = $asn1->encodeOctetString(\str_repeat('X', 64));

        return [
            'a second element after the parameters' => [
                $asn1->encodeSequence($oid . $asn1->encodeNull() . $chosen),
                'Trailing bytes in the signature AlgorithmIdentifier',
            ],
            'parameters that are neither absent nor NULL' => [
                $asn1->encodeSequence($oid . $chosen),
                'Unsupported signature AlgorithmIdentifier parameters',
            ],
            'not a SEQUENCE at all' => [$asn1->encodeOctetString($oid), 'Invalid OCSP signatureAlgorithm'],
        ];
    }

    #[DataProvider('rewrittenSignatureAlgorithmProvider')]
    public function testParseResponseBoundsTheSignatureAlgorithm(string $algorithmId, string $message): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData($this->der->singleResponse($request->certId));
        $basic = $this->asn1->encodeSequence(
            $responseData . $algorithmId . $this->der->bitString(Authority::ocsp()->sign($responseData)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $basic), $request, self::NOW);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function shadowedSingleResponseProvider(): array
    {
        $asn1 = new Asn1();
        $der = new Der($asn1);

        return [
            'unknown critical singleExtension' => [
                $der->extension('1.2.3.4.5.6.7', "\x05\x00", true),
                'Unsupported critical OCSP singleExtension',
            ],
        ];
    }

    #[DataProvider('shadowedSingleResponseProvider')]
    public function testParseResponseHoldsEveryMatchingEntryToTheCriticalityRule(
        string $extensions,
        string $message,
    ): void {
        // matchingSingleResponses() returns every entry that answers the CertID,
        // since two of them may disagree, and the RFC 6960 section 4.4 criticality
        // rule reaches each of them wherever it sits.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData(
            $this->der->singleResponse($request->certId)
                . $this->der->singleResponse($request->certId, extensions: $extensions),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($responseData)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseHoldsEveryMatchingEntryToTheStatusRule(): void
    {
        // The same rule for the status itself, so the order of two entries for one
        // CertID does not decide whether the response is accepted.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData(
            $this->der->singleResponse($request->certId) . $this->der->singleResponse($request->certId, "\x82\x00"),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/The certificate status is unknown/');
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($responseData)),
            $request,
            self::NOW,
        );
    }

    /**
     * SingleResponse entries about another certificate, malformed past their CertID.
     *
     * @return array<string, array{string, string}>
     */
    public static function malformedForeignEntryProvider(): array
    {
        $asn1 = new Asn1();
        $der = new Der($asn1);
        $certId = (new Client($asn1))->build(
            Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca.pem')),
            Authority::responder()->certDer,
        )->certId;

        $marker = $asn1->encodeOctetString(\str_repeat('P', 64));

        return [
            'no certStatus and no thisUpdate' => [
                $asn1->encodeSequence($certId),
                'Malformed ASN.1 structure',
            ],
            'chosen bytes after thisUpdate' => [
                $asn1->encodeSequence($certId . "\x80\x00" . $der->generalizedTime(Der::RECENT_THIS_UPDATE) . $marker),
                'Invalid OCSP singleExtension field after the extensions position',
            ],
            'thisUpdate is an OCTET STRING' => [
                $asn1->encodeSequence($certId . "\x80\x00" . $marker),
                'Invalid OCSP thisUpdate',
            ],
            'chosen bytes after the singleExtensions' => [
                $asn1->encodeSequence(
                    $certId
                    . "\x80\x00"
                    . $der->generalizedTime(Der::RECENT_THIS_UPDATE)
                    . $asn1->encodeContext(1, $asn1->encodeSequence($der->extension('1.2.3.4.5.6.7')))
                    . $marker,
                ),
                'Trailing bytes after the OCSP singleExtensions',
            ],
        ];
    }

    #[DataProvider('malformedForeignEntryProvider')]
    public function testParseResponseHoldsAnEntryAboutAnotherCertificateToItsShape(string $entry, string $message): void
    {
        // An entry answering about another certificate is held to its shape too,
        // parseResponse() returning the caller's string unchanged for the DSS
        // emitter. Ltv\Crl holds every revocation entry to its shape wherever it
        // sits.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData($this->der->singleResponse($request->certId) . $entry);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($responseData)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseRefusesAnEmptySingleExtensionsWrapper(): void
    {
        // An EXPLICIT tag wraps exactly one element (X.690 section 8.14), so A1 00
        // is refused rather than read as an absent field.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $single = $this->asn1->encodeSequence(
            $request->certId . "\x80\x00" . $this->der->generalizedTime(self::NOW - 3600) . "\xA1\x00",
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Empty OCSP singleExtensions/');
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($this->der->responseData($single))),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseHoldsEveryMatchingEntryToTheValidityInterval(): void
    {
        // The same rule for RFC 6960 section 3.2 rules 5 and 6: the validity
        // interval is checked on every match, not only the first.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData(
            $this->der->singleResponse($request->certId)
                . $this->der->singleResponse($request->certId, nextUpdate: self::NOW - 50_000),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/has expired/');
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($responseData)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseKeepsTheRevokedVerdictAheadOfAStaleEntry(): void
    {
        // Revoked outranks a stale entry for the same CertID.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $revoked = "\xA1" . $this->asn1->encodeLength(17) . $this->der->generalizedTime(1_700_000_000);
        $responseData = $this->der->responseData(
            $this->der->singleResponse($request->certId, nextUpdate: self::NOW - 50_000)
                . $this->der->singleResponse($request->certId, $revoked),
        );

        $this->expectException(RevokedException::class);
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($responseData)),
            $request,
            self::NOW,
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function paddedCertIdAlgorithmProvider(): array
    {
        $asn1 = new Asn1();
        $sha1 = $asn1->encodeObjectIdentifier('1.3.14.3.2.26');

        return [
            'two extra elements after the OID' => [
                $asn1->encodeSequence($sha1 . $asn1->encodeNull() . $asn1->encodeOctetString(\str_repeat('M', 64))),
            ],
            'a megabyte of parameters' => [
                $asn1->encodeSequence($sha1 . $asn1->encodeOctetString(\str_repeat("\x00", 1 << 20))),
            ],
        ];
    }

    #[DataProvider('paddedCertIdAlgorithmProvider')]
    public function testParseResponseBoundsTheCertIdAlgorithmIdentifier(string $algorithmId): void
    {
        // The CertID comparison is by value, so the AlgorithmIdentifier is bounded
        // rather than compared as raw DER. An entry whose CertID carries padding no
        // longer parses, and matchingSingleResponses() skips it.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $offset = 0;
        $certId = $this->asn1->readTlv($request->certId, $offset);
        $inner = 0;
        $this->asn1->readTlv($certId['value'], $inner);

        $padded = $this->asn1->encodeSequence($algorithmId . \substr($certId['value'], $inner));

        $responseData = $this->der->responseData($this->der->singleResponse($padded));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not match the request/');
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($responseData)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseAcceptsACertIdAlgorithmWithoutNullParameters(): void
    {
        // RFC 3279 requires the SHA-1 identifier to carry NULL parameters, but a
        // responder that rebuilds the CertID with them absent names the same
        // certificate, so the comparison is by value.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $offset = 0;
        $certId = $this->asn1->readTlv($request->certId, $offset);
        $inner = 0;
        $this->asn1->readTlv($certId['value'], $inner);

        $rebuilt = $this->asn1->encodeSequence(
            $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier('1.3.14.3.2.26'))
                . \substr($certId['value'], $inner),
        );

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse($rebuilt))),
        );

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function malformedResponseDataHeadProvider(): array
    {
        $asn1 = new Asn1();

        return [
            'producedAt is an OCTET STRING' => [
                '',
                $asn1->encodeOctetString(\str_repeat('M', 64)),
                'Invalid OCSP producedAt',
            ],
            'producedAt is not a valid time' => [
                '',
                "\x18\x0F" . '99999999999999Z',
                'GeneralizedTime',
            ],
            'version [0] holds chosen bytes' => [
                $asn1->encodeContext(0, $asn1->encodeOctetString(\str_repeat('M', 64))),
                '',
                'Invalid OCSP ResponseData version',
            ],
            'version [0] holds two elements' => [
                $asn1->encodeContext(0, $asn1->encodeInteger(0) . $asn1->encodeNull()),
                '',
                'Invalid OCSP ResponseData version',
            ],
        ];
    }

    #[DataProvider('malformedResponseDataHeadProvider')]
    public function testParseResponseBoundsTheResponseDataHead(
        string $version,
        string $producedAt,
        string $message,
    ): void {
        // Both fields are inside tbsResponseData and are read rather than stepped
        // over, the response being archived verbatim in an /OCSPs stream.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responses = $this->asn1->encodeSequence($this->der->singleResponse($request->certId));
        $responseData = $this->asn1->encodeSequence(
            $version
            . Authority::ocsp()->responderIdByName($this->asn1)
            . ($producedAt === '' ? $this->der->generalizedTime(1_700_000_000) : $producedAt)
            . $responses,
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($message, '/') . '/');
        $client->parseResponse(
            $this->der->ocspResponseBytes(0, $this->der->basicResponse($responseData)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseRefusesADelegatedResponderWhoseKeyUsageForbidsSigning(): void
    {
        // RFC 5280 section 4.2.1.3 reserves digitalSignature for a signature that is
        // not over a certificate or a CRL, which is what a response carries. The
        // OCSPSigning purpose says what the key is for, the key usage whether it may
        // sign at all. Ltv\Crl and Signer ask the same of the certificates they gate.
        $responder = Authority::unsigningResponder();
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $der = new Der($this->asn1, Authority::ocsp());
        $responseData = $der->responseData(
            $der->singleResponse($request->certId),
            $responder->responderIdByName($this->asn1),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/key usage does not admit signing/');
        $client->parseResponse(
            $der->ocspResponseBytes(0, $der->basicResponse($responseData, [$responder->certDer], $responder)),
            $request,
            self::NOW,
        );
    }

    public function testParseResponseRejectsAnOversizedCertificateBag(): void
    {
        // Every bag member naming the ResponderID costs a key load, two DER parses,
        // and a signature check, and the search runs to the end of the bag, so the
        // bag is bounded as Signer bounds a timestamp token's.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $bag = \array_fill(0, Client::MAX_RESPONDER_CERTIFICATES + 1, Authority::responder()->certDer);
        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData($this->der->singleResponse($request->certId)),
            $bag,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/embeds more than ' . Client::MAX_RESPONDER_CERTIFICATES . '/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRefusesANonCertificateBagMember(): void
    {
        // RFC 6960 section 4.2.1 shapes certs [0] as a SEQUENCE OF Certificate,
        // not as the CMS CertificateSet, so a tagged alternative is refused rather
        // than skipped.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $bag = [
            $this->asn1->encodeContext(3, $this->asn1->encodeInteger(1)),
            Authority::responder()->certDer,
        ];
        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData($this->der->singleResponse($request->certId)),
            $bag,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP responder certificates/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRefusesTrailingBytesInTheBasicOcspResponse(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $basic = $this->der->basicResponse($this->der->responseData($this->der->singleResponse($request->certId)), [
            Authority::responder()->certDer,
        ]);

        $offset = 0;
        $sequence = $this->asn1->readTlv($basic, $offset);
        $padded = $this->asn1->encodeSequence($sequence['value'] . $this->asn1->encodeNull());

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes in the BasicOCSPResponse/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $padded), $request, self::NOW);
    }

    public function testParseResponseRefusesTrailingBytesInsideTheCertificateBag(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $basic = $this->der->basicResponse($this->der->responseData($this->der->singleResponse($request->certId)), [
            Authority::responder()->certDer,
        ]);

        $offset = 0;
        $sequence = $this->asn1->readTlv($basic, $offset);
        $inner = 0;
        $fields = [];
        while ($inner < \strlen($sequence['value'])) {
            $fields[] = $this->asn1->readTlv($sequence['value'], $inner);
        }

        // tbsResponseData, signatureAlgorithm, signature, certs [0]
        $bag = \end($fields);
        $this->assertIsArray($bag);
        $padded = $this->asn1->encodeSequence(
            \implode('', \array_map(static fn(array $f): string => $f['raw'], \array_slice($fields, 0, -1)))
                . $this->asn1->encodeContext(0, $bag['value'] . $this->asn1->encodeNull()),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP responder certificates/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $padded), $request, self::NOW);
    }

    public function testParseResponseAcceptsACertificateBagAtTheBound(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $bag = \array_fill(0, Client::MAX_RESPONDER_CERTIFICATES, Authority::responder()->certDer);
        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData($this->der->singleResponse($request->certId)),
            $bag,
        ));

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testFetchRejectsNonStringTransportResult(): void
    {
        $transport = static fn(string $url, string $request): int => \strlen($url . $request);
        $this->expectException(Exception::class);
        (new Client($this->asn1))->fetch('http://x', $this->caDer, $this->leafDer, $transport);
    }

    /**
     * @return list<array{int<0, 255>, string}>
     */
    public static function errorStatusProvider(): array
    {
        return [
            [1, 'malformedRequest'],
            [2, 'internalError'],
            [3, 'tryLater'],
            [5, 'sigRequired'],
            [6, 'unauthorized'],
        ];
    }

    /**
     * @param int<0, 255> $status
     */
    #[DataProvider('errorStatusProvider')]
    public function testParseResponseRejectsErrorStatus(int $status, string $name): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($name, '/') . '/');
        $client->parseResponse($this->der->ocspResponseBytes($status, null), $request, self::NOW);
    }

    public function testParseResponseRejectsEmpty(): void
    {
        $client = new Client($this->asn1);
        $this->expectException(Exception::class);
        $client->parseResponse('', $client->build($this->caDer, $this->leafDer), self::NOW);
    }

    public function testParseResponseRejectsSuccessWithoutBytes(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Missing OCSP response bytes/');
        $client->parseResponse($this->der->ocspResponseBytes(0, null), $request, self::NOW);
    }

    public function testParseResponseRejectsUnsupportedResponseType(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $bytes = $this->asn1->encodeContext(
            0,
            $this->asn1->encodeSequence(
                $this->asn1->encodeObjectIdentifier('1.3.6.1.5.5.7.48.1.9') . $this->asn1->encodeOctetString('x'),
            ),
        );
        $response = $this->asn1->encodeSequence($this->der->enumerated(0) . $bytes);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported OCSP response type/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsUnrelatedCertId(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // A response about the CA certificate rather than the leaf.
        $other = $client->build($this->caDer, $this->caDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not match the request/');
        $client->parseResponse($this->der->ocspResponse($other->certId), $request, self::NOW);
    }

    public function testParseResponseRejectsRevoked(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $revoked = "\xA1" . $this->asn1->encodeLength(17) . $this->der->generalizedTime(1_700_000_000);
        $response = $this->der->ocspResponse($request->certId, $revoked);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/revoked/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsUnknownStatus(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponse($request->certId, "\x82\x00");

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/unknown/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsExpiredResponse(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // Recent enough to pass the age bound, so it is nextUpdate that refuses it.
        $response = $this->der->ocspResponse($request->certId, "\x80\x00", 1_799_900_000, 1_799_950_000);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/expired/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsAStaleResponseWithAFarFutureNextUpdate(): void
    {
        // RFC 6960 section 3.2 rule 5 stands on its own, so the age bound applies
        // however long a nextUpdate declares the answer to hold.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponse($request->certId, "\x80\x00", 1_500_000_000, 1_900_000_000);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/too old/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAppliesNoAgeBoundWhenTheLimitIsZero(): void
    {
        $client = new Client($this->asn1, null, null, 0);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponse($request->certId, "\x80\x00", 1_500_000_000, 1_900_000_000);

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAnUnknownCriticalSingleExtension(): void
    {
        // RFC 6960 section 4.4: an extension marked critical may qualify what the
        // status means, so one this reader cannot process makes the response
        // unusable.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                "\x80\x00",
                Der::RECENT_THIS_UPDATE,
                1_900_000_000,
                $this->der->extension('1.3.6.1.4.1.99999.1', "\x05\x00", true),
            ))),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported critical OCSP singleExtension/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsAnUnknownCriticalResponseExtension(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId),
                null,
                1_700_000_000,
                '',
                $this->der->extension('1.3.6.1.4.1.99999.1', "\x05\x00", true),
            )),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Unsupported critical OCSP responseExtension/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testResponseExtensionsAreReadAtTheTagRfc6960Assigns(): void
    {
        // RFC 6960 section 4.2.1 puts responseExtensions at [1], the tail field of
        // ResponseData, so it is read at that tag alone.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData(
            $this->der->singleResponse($request->certId),
            null,
            1_700_000_000,
            '',
            $this->der->extension('1.3.6.1.5.5.7.48.1.2', $this->asn1->encodeOctetString('nonce')),
        );

        $offset = 0;
        $sequence = $this->asn1->readTlv($responseData, $offset);

        $inner = 0;
        $this->asn1->readTlv($sequence['value'], $inner); // responderID
        $this->asn1->readTlv($sequence['value'], $inner); // producedAt
        $this->asn1->readTlv($sequence['value'], $inner); // responses

        $this->assertSame(0xA1, $this->asn1->readTlv($sequence['value'], $inner)['tag']);
        $this->assertSame(\strlen($sequence['value']), $inner);
    }

    public function testParseResponseRefusesAFieldAheadOfTheResponseExtensions(): void
    {
        // responseExtensions is the tail field of ResponseData, so an element at the
        // cursor carrying another tag is refused rather than reported as absent.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::responder();

        $responseData = $this->der->responseData(
            $this->der->singleResponse($request->certId),
            $responder->responderIdByName($this->asn1),
            1_700_000_000,
            '',
            $this->der->extension('1.2.3.4.5.6.7', "\x05\x00", true),
        );

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->shiftTail($responseData),
            [$responder->certDer],
            $responder,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP responseExtension field after the extensions position/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRefusesAFieldAheadOfTheSingleExtensions(): void
    {
        // The same gap on the SingleResponse, where singleExtensions is the tail field.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::responder();

        $single = $this->der->singleResponse(
            $request->certId,
            "\x80\x00",
            Der::RECENT_THIS_UPDATE,
            1_900_000_000,
            $this->der->extension('1.2.3.4.5.6.7', "\x05\x00", true),
        );

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData($this->shiftTail($single), $responder->responderIdByName($this->asn1)),
            [$responder->certDer],
            $responder,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP singleExtension field after the extensions position/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRefusesBytesAfterTheResponseExtensions(): void
    {
        // The field is the tail of ResponseData, so nothing may follow it.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::responder();

        $responseData = $this->der->responseData(
            $this->der->singleResponse($request->certId),
            $responder->responderIdByName($this->asn1),
            1_700_000_000,
            '',
            $this->der->extension('1.3.6.1.5.5.7.48.1.2', $this->asn1->encodeOctetString('nonce')),
        );

        $offset = 0;
        $sequence = $this->asn1->readTlv($responseData, $offset);

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->asn1->encodeSequence($sequence['value'] . $this->asn1->encodeOctetString('trailing')),
            [$responder->certDer],
            $responder,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes after the OCSP responseExtensions/');
        $client->parseResponse($response, $request, self::NOW);
    }

    /**
     * Re-encode a SEQUENCE with an unread [2] element inserted before its last field.
     */
    private function shiftTail(string $sequenceDer): string
    {
        $offset = 0;
        $sequence = $this->asn1->readTlv($sequenceDer, $offset);

        $inner = 0;
        $head = '';
        $last = '';
        while ($inner < \strlen($sequence['value'])) {
            $head .= $last;
            $last = $this->asn1->readTlv($sequence['value'], $inner)['raw'];
        }

        return $this->asn1->encodeSequence($head . $this->asn1->encodeContext(2, '') . $last);
    }

    public function testParseResponseAcceptsACriticalArchiveCutoffExtension(): void
    {
        // id-pkix-ocsp-archive-cutoff is { id-pkix-ocsp 6 } (RFC 6960 appendix B.2).
        // It states how far back the responder keeps records and narrows nothing
        // about what a good status means.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                "\x80\x00",
                Der::RECENT_THIS_UPDATE,
                1_900_000_000,
                $this->der->extension('1.3.6.1.5.5.7.48.1.6', $this->der->generalizedTime(1_500_000_000), true),
            ))),
        );

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsACriticalCrlReferencesExtension(): void
    {
        // id-pkix-ocsp-crl is { id-pkix-ocsp 3 }: CRL References, which this reader
        // does not process, so marked critical it makes the response unusable.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                "\x80\x00",
                Der::RECENT_THIS_UPDATE,
                1_900_000_000,
                $this->der->extension('1.3.6.1.5.5.7.48.1.3', "\x05\x00", true),
            ))),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches(
            '/Unsupported critical OCSP singleExtension: 1\.3\.6\.1\.5\.5\.7\.48\.1\.3/',
        );
        $client->parseResponse($response, $request, self::NOW);
    }

    /**
     * Malformed singleExtensions the reader has to refuse rather than walk past.
     *
     * @return array<string, array{string}>
     */
    public static function malformedExtensionProvider(): array
    {
        $asn1 = new Asn1();

        return [
            'entry not a sequence' => [$asn1->encodeInteger(1)],
            'type not an oid' => [$asn1->encodeSequence($asn1->encodeInteger(1) . $asn1->encodeOctetString('v'))],
            'value not an octet string' => [$asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('1.3.6.1.4.1.99999.1') . $asn1->encodeInteger(1),
            )],
            'value not an octet string after critical' => [$asn1->encodeSequence(
                $asn1->encodeObjectIdentifier('1.3.6.1.4.1.99999.1') . $asn1->encodeBoolean(true)
                    . $asn1->encodeInteger(1),
            )],
        ];
    }

    #[DataProvider('malformedExtensionProvider')]
    public function testParseResponseRejectsAMalformedSingleExtension(string $extension): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                "\x80\x00",
                Der::RECENT_THIS_UPDATE,
                1_900_000_000,
                $extension,
            ))),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP singleExtension/');
        $client->parseResponse($response, $request, self::NOW);
    }

    /**
     * Extension encodings the shared codec refuses that an open-coded walk let past.
     *
     * @return array<string, array{string, string}>
     */
    public static function strictExtensionProvider(): array
    {
        $asn1 = new Asn1();
        $oid = $asn1->encodeObjectIdentifier('1.3.6.1.4.1.99999.1');
        $value = $asn1->encodeOctetString("\x05\x00");

        return [
            'critical BOOLEAN of zero length' => [
                $asn1->encodeSequence($oid . "\x01\x00" . $value),
                'Invalid OCSP singleExtension critical flag',
            ],
            'trailing content after extnValue' => [
                $asn1->encodeSequence($oid . $value . $asn1->encodeInteger(9)),
                'Trailing bytes in OCSP singleExtension',
            ],
            'the same extension twice' => [
                $asn1->encodeSequence($oid . $value) . $asn1->encodeSequence($oid . $value),
                'Duplicate OCSP singleExtension: 1.3.6.1.4.1.99999.1',
            ],
        ];
    }

    #[DataProvider('strictExtensionProvider')]
    public function testParseResponseHoldsSingleExtensionsToTheSameRulesAsACrl(
        string $extension,
        string $expected,
    ): void {
        // An Extension is the same structure wherever it sits, so this reader shares
        // the codec the CRL and TSA readers use: a BOOLEAN is one octet (X.690
        // section 8.2.1), extnValue is the last field, and RFC 5280 section 4.2
        // admits one instance of each type.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                "\x80\x00",
                Der::RECENT_THIS_UPDATE,
                1_900_000_000,
                $extension,
            ))),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/' . \preg_quote($expected, '/') . '/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsSingleExtensionsThatAreNotASequence(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // singleExtensions [1] EXPLICIT wraps an Extensions SEQUENCE, not an INTEGER.
        $single = $this->asn1->encodeSequence(
            $request->certId . "\x80\x00" . $this->der->generalizedTime(Der::RECENT_THIS_UPDATE)
                . $this->asn1->encodeContext(1, $this->asn1->encodeInteger(1)),
        );

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse($this->der->responseData($single)));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP singleExtensions/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAcceptsAnUnknownExtensionThatIsNotCritical(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                "\x80\x00",
                Der::RECENT_THIS_UPDATE,
                1_900_000_000,
                $this->der->extension('1.3.6.1.4.1.99999.1'),
            ))),
        );

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseAcceptsACriticalNonceExtension(): void
    {
        // id-pkix-ocsp-nonce narrows nothing about what a good status means.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId),
                null,
                1_700_000_000,
                '',
                $this->der->extension('1.3.6.1.5.5.7.48.1.2', $this->asn1->encodeOctetString('nonce'), true),
            )),
        );

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseLetsRevokedWinOverAnEarlierGoodForTheSameCertId(): void
    {
        // Among two answers for one CertID, revoked wins wherever it sits.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $revoked = $this->asn1->encodeContext(1, $this->der->generalizedTime(1_799_000_000));
        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId) . $this->der->singleResponse($request->certId, $revoked),
            )),
        );

        $this->expectException(RevokedException::class);
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseLetsRevokedWinOverAStructuralFaultInAForeignEntry(): void
    {
        // Both refuse the response, under different codes, and revoked outranks a
        // structural fault in a later entry. Ltv\Crl::checkNotRevoked() applies the
        // same precedence among the entries of one list.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $revoked = $this->asn1->encodeContext(1, $this->der->generalizedTime(1_799_000_000));
        $foreign = $this->asn1->encodeSequence(
            $this->foreignCertId() . "\x80\x00" . $this->asn1->encodeOctetString('not a thisUpdate'),
        );

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId, $revoked) . $foreign,
            )),
        );

        $this->expectException(RevokedException::class);
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseReportsAStructuralFaultAheadOfTheRevokedEntry(): void
    {
        // The limit of the rule above: a fault ahead of the match leaves no verdict
        // to prefer, so the response is refused as malformed.
        // Ltv\Crl::checkNotRevoked() stops at the same place.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $revoked = $this->asn1->encodeContext(1, $this->der->generalizedTime(1_799_000_000));
        $foreign = $this->asn1->encodeSequence(
            $this->foreignCertId() . "\x80\x00" . $this->asn1->encodeOctetString('not a thisUpdate'),
        );

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $foreign . $this->der->singleResponse($request->certId, $revoked),
            )),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP thisUpdate/');
        $client->parseResponse($response, $request, self::NOW);
    }

    /**
     * A well-formed CertID naming a certificate the request did not ask about.
     */
    private function foreignCertId(): string
    {
        return (new Client($this->asn1))->build($this->caDer, Authority::responder()->certDer)->certId;
    }

    /**
     * revoked [1] alternatives that are not the RevokedInfo RFC 6960 section 4.2.1 gives.
     *
     * @return array<string, array{string}>
     */
    public static function malformedRevokedInfoProvider(): array
    {
        $asn1 = new Asn1();
        $time = "\x18\x0F" . '20261231235959Z';

        return [
            'primitive, carrying chosen octets' => ["\x81" . $asn1->encodeLength(64) . \str_repeat('R', 64)],
            'primitive, carrying a revocationTime' => ["\x81" . $asn1->encodeLength(\strlen($time)) . $time],
            'constructed and empty' => ["\xA1\x00"],
            'revocationTime that is not a GeneralizedTime' => [
                $asn1->encodeContext(1, $asn1->encodeOctetString('20261231235959Z')),
            ],
            'revocationTime that is not a DER instant' => [$asn1->encodeContext(1, "\x18\x04" . '2026')],
            'revocationReason that is not the EXPLICIT wrapper' => [
                $asn1->encodeContext(1, $time . "\x0A\x01\x01"),
            ],
            'revocationReason that is not a CRLReason' => [
                $asn1->encodeContext(1, $time . $asn1->encodeContext(0, $asn1->encodeInteger(1))),
            ],
            'non-minimal revocationReason' => [
                $asn1->encodeContext(1, $time . $asn1->encodeContext(0, "\x0A\x02\x00\x01")),
            ],
            'a field after the revocationReason' => [
                $asn1->encodeContext(1, $time . $asn1->encodeContext(0, "\x0A\x01\x01") . $asn1->encodeNull()),
            ],
        ];
    }

    #[DataProvider('malformedRevokedInfoProvider')]
    public function testParseResponseHoldsAForeignRevokedEntryToRevokedInfo(string $status): void
    {
        // certStatus() leaves revoked [1] open for the entry that answers the
        // request, a responder that emits it primitively having still said revoked.
        // A foreign entry's verdict is never read, so it is held to the whole
        // alternative by assertForeignRevokedInfo().
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $foreign = $this->asn1->encodeSequence(
            $this->foreignCertId() . $status . $this->der->generalizedTime(Der::RECENT_THIS_UPDATE),
        );

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId) . $foreign,
            )),
        );

        $this->expectException(Exception::class);
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAcceptsAWellFormedForeignRevokedEntry(): void
    {
        // The control: a foreign entry stating revoked as RFC 6960 shapes it, with
        // and without the optional reason, is accepted.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $time = $this->der->generalizedTime(1_799_000_000);

        foreach ([$time, $time . $this->asn1->encodeContext(0, "\x0A\x01\x01")] as $label => $revokedInfo) {
            $foreign = $this->asn1->encodeSequence(
                $this->foreignCertId() . $this->asn1->encodeContext(1, $revokedInfo)
                    . $this->der->generalizedTime(Der::RECENT_THIS_UPDATE),
            );

            $response = $this->der->ocspResponseBytes(
                0,
                $this->der->basicResponse($this->der->responseData(
                    $this->der->singleResponse($request->certId) . $foreign,
                )),
            );

            $this->assertSame($response, $client->parseResponse($response, $request, self::NOW), (string) $label);
        }
    }

    public function testParseResponseLetsRevokedWinOverAMalformedForeignRevokedEntry(): void
    {
        // The precedence holds for this refusal too: the entry answering the request
        // says revoked, and that is the verdict the caller acts on.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $foreign = $this->asn1->encodeSequence(
            $this->foreignCertId() . "\x81" . $this->asn1->encodeLength(64) . \str_repeat('R', 64)
                . $this->der->generalizedTime(Der::RECENT_THIS_UPDATE),
        );

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse(
                    $request->certId,
                    $this->asn1->encodeContext(1, $this->der->generalizedTime(1_799_000_000)),
                )
                    . $foreign,
            )),
        );

        $this->expectException(RevokedException::class);
        $client->parseResponse($response, $request, self::NOW);
    }

    /**
     * certStatus values that name no alternative of the RFC 6960 section 4.2.1 CHOICE.
     *
     * @return array<string, array{string}>
     */
    public static function malformedCertStatusProvider(): array
    {
        $asn1 = new Asn1();
        $marker = \str_repeat('P', 64);

        return [
            'good [0] carrying content' => ["\x80" . $asn1->encodeLength(64) . $marker],
            'good [0] constructed and carrying content' => ["\xA0" . $asn1->encodeLength(64) . $marker],
            // A NULL is primitive as well as empty, so an empty constructed wrapper
            // is refused.
            'good [0] constructed and empty' => ["\xA0\x00"],
            'unknown [2] constructed and empty' => ["\xA2\x00"],
            'unknown [2] carrying content' => ["\x82" . $asn1->encodeLength(64) . $marker],
            'a tag outside the CHOICE' => ["\x85\x00"],
            'a constructed tag outside the CHOICE' => ["\xA5" . $asn1->encodeLength(64) . $marker],
        ];
    }

    #[DataProvider('malformedCertStatusProvider')]
    public function testParseResponseHoldsTheCertStatusToTheChoice(string $status): void
    {
        // good [0] IMPLICIT NULL and unknown [2] IMPLICIT UnknownInfo, itself a
        // NULL, have no content octets (X.690 section 8.8.2), and the CHOICE has no
        // fourth alternative.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP certStatus/');
        $client->parseResponse($this->der->ocspResponse($request->certId, $status), $request, self::NOW);
    }

    public function testParseResponseTreatsAPrimitivelyEncodedRevokedAsRevoked(): void
    {
        // revoked [1] wraps a SEQUENCE and so has to be constructed, but a responder
        // that emits it primitively has still said revoked.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $revokedInfo = $this->der->generalizedTime(1_799_000_000);
        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                "\x81" . \chr(\strlen($revokedInfo)) . $revokedInfo,
            ))),
        );

        $this->expectException(RevokedException::class);
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsACertStatusThatIsNotAContextTag(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
                $request->certId,
                $this->asn1->encodeInteger(1),
            ))),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP certStatus/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsFutureResponse(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponse($request->certId, "\x80\x00", 1_900_000_000, 1_950_000_000);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not yet valid/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAcceptsARecentResponseWithoutNextUpdate(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // nextUpdate is OPTIONAL (RFC 6960 section 4.2.2.1), so a fresh answer
        // without one stands on its thisUpdate alone.
        $response = $this->der->ocspResponse($request->certId, "\x80\x00", self::NOW - 3600, null);

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAStaleResponseWithoutNextUpdate(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // RFC 6960 section 3.2 rule 5, applied because no nonce is sent.
        $thisUpdate = self::NOW - Client::DEFAULT_MAX_AGE - 86_400;
        $response = $this->der->ocspResponse($request->certId, "\x80\x00", $thisUpdate, null);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/too old/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAgeLimitIsConfigurable(): void
    {
        $request = (new Client($this->asn1))->build($this->caDer, $this->leafDer);
        $response = $this->der->ocspResponse($request->certId, "\x80\x00", self::NOW - 86_400, null);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/too old/');
        (new Client($this->asn1, maxAge: 3600))->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAgeLimitCanBeDisabled(): void
    {
        $request = (new Client($this->asn1))->build($this->caDer, $this->leafDer);
        $response = $this->der->ocspResponse($request->certId, "\x80\x00", 1_600_000_000, null);

        $this->assertSame($response, (new Client($this->asn1, maxAge: 0))->parseResponse(
            $response,
            $request,
            self::NOW,
        ));
    }

    public function testConstructorRejectsANegativeAgeLimit(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/age limit/');
        new Client($this->asn1, maxAge: -1);
    }

    public function testClockSkewIsConfigurable(): void
    {
        // A response produced an hour ahead is outside the default skew and inside
        // a widened one, as on the TSA side.
        $request = (new Client($this->asn1))->build($this->caDer, $this->leafDer);
        $response = $this->der->ocspResponse($request->certId, "\x80\x00", self::NOW + 3600, self::NOW + 86_400);

        $this->assertSame($response, (new Client($this->asn1, clockSkew: 7200))->parseResponse(
            $response,
            $request,
            self::NOW,
        ));
    }

    public function testTheDefaultClockSkewRejectsWhatAWidenedOneAccepts(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $response = $this->der->ocspResponse($request->certId, "\x80\x00", self::NOW + 3600, self::NOW + 86_400);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not yet valid/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testConstructorRejectsANegativeClockSkew(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/clock skew/');
        new Client($this->asn1, clockSkew: -1);
    }

    public function testParseResponseRejectsResponseWithNoSingleResponse(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $basic = $this->der->basicResponse($this->der->responseData(''));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/carries no certificate status/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $basic), $request, self::NOW);
    }

    /**
     * Malformed responses that never reach the CertID comparison.
     *
     * @return array<string, array{callable(Asn1, Der): string}>
     */
    public static function malformedResponseProvider(): array
    {
        return [
            'not a sequence' => [static fn(Asn1 $asn1, Der $_der): string => $asn1->encodeInteger(0)],
            'trailing bytes' => [
                static fn(Asn1 $_asn1, Der $der): string => $der->ocspResponseBytes(0, null) . "\x00",
            ],
            'status not enumerated' => [
                static fn(Asn1 $asn1, Der $_der): string => $asn1->encodeSequence($asn1->encodeInteger(0)),
            ],
            'response bytes not tagged' => [
                static fn(Asn1 $asn1, Der $der): string => $asn1->encodeSequence(
                    $der->enumerated(0) . $asn1->encodeSequence(''),
                ),
            ],
            'payload not an octet string' => [
                static fn(Asn1 $asn1, Der $der): string => $asn1->encodeSequence(
                    $der->enumerated(0)
                        . $asn1->encodeContext(
                            0,
                            $asn1->encodeSequence(
                                $asn1->encodeObjectIdentifier(Der::OID_OCSP_BASIC) . $asn1->encodeInteger(1),
                            ),
                        ),
                ),
            ],
            'basic response not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => $der->ocspResponseBytes(0, $asn1->encodeInteger(1)),
            ],
            'response data not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => $der->ocspResponseBytes(
                    0,
                    $asn1->encodeSequence($asn1->encodeInteger(1)),
                ),
            ],
            'single response not a sequence' => [
                static fn(Asn1 $asn1, Der $der): string => $der->ocspResponseBytes(
                    0,
                    $asn1->encodeSequence($asn1->encodeSequence(
                        $asn1->encodeContext(1, $asn1->encodeSequence('')) . $der->generalizedTime(1_700_000_000)
                            . $asn1->encodeSequence($asn1->encodeInteger(1)),
                    )),
                ),
            ],
        ];
    }

    /**
     * @param callable(Asn1, Der): string $build
     */
    #[DataProvider('malformedResponseProvider')]
    public function testParseResponseRejectsMalformedStructures(callable $build): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $this->expectException(Exception::class);
        $client->parseResponse($build($this->asn1, $this->der), $request, self::NOW);
    }

    public function testParseResponseAcceptsAnExplicitVersionField(): void
    {
        // version [0] EXPLICIT DEFAULT v1 is omitted by a conforming responder, but
        // it is legal to send it.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $basic = $this->der->basicResponse($this->der->responseData(
            $this->der->singleResponse($request->certId, "\x80\x00", self::NOW - 3600, null),
            null,
            1_700_000_000,
            $this->asn1->encodeContext(0, $this->asn1->encodeInteger(0)),
        ));

        $response = $this->der->ocspResponseBytes(0, $basic);
        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsANonGeneralizedTimeThisUpdate(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $single = $this->asn1->encodeSequence(
            $request->certId . "\x80\x00" . $this->asn1->encodeOctetString('20231114221320Z'),
        );
        $basic = $this->der->basicResponse($this->der->responseData($single));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP thisUpdate/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $basic), $request, self::NOW);
    }

    public function testParseResponseIgnoresSingleExtensionsInPlaceOfNextUpdate(): void
    {
        // singleExtensions is [1]; only [0] is nextUpdate, so the validity check
        // stops rather than reading the extensions as a time.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $single = $this->asn1->encodeSequence(
            $request->certId . "\x80\x00" . $this->der->generalizedTime(self::NOW - 3600)
                . $this->asn1->encodeContext(1, $this->asn1->encodeSequence('')),
        );
        $basic = $this->der->basicResponse($this->der->responseData($single));

        $response = $this->der->ocspResponseBytes(0, $basic);
        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAForgedSignature(): void
    {
        // RFC 6960 section 3.2: the signature on the response must verify.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData($this->der->singleResponse($request->certId));
        $basic = $this->asn1->encodeSequence(
            $responseData . $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID))
                . $this->der->bitString('not a signature'),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not verify/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $basic), $request, self::NOW);
    }

    public function testParseResponseRejectsATamperedResponse(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // A genuinely signed revoked response, with the status flipped to good.
        $revoked = "\xA1" . $this->asn1->encodeLength(17) . $this->der->generalizedTime(1_700_000_000);
        $signed = $this->der->basicResponse($this->der->responseData($this->der->singleResponse(
            $request->certId,
            $revoked,
        )));
        $tampered = \str_replace($revoked, "\x80\x00" . \str_repeat("\x00", 17), $signed);

        $this->expectException(Exception::class);
        $client->parseResponse($this->der->ocspResponseBytes(0, $tampered), $request, self::NOW);
    }

    public function testParseResponseAcceptsADelegatedResponder(): void
    {
        // RFC 6960 section 4.2.2.2: a responder the issuer delegated to, by issuing it
        // a certificate carrying id-kp-OCSPSigning.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::responder();

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $responder->responderIdByName($this->asn1),
            ),
            [$responder->certDer],
            $responder,
        ));

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAnExpiredDelegatedResponder(): void
    {
        // RFC 6960 section 3.2 rule 4 asks for a responder that is currently
        // authorised, and openssl_x509_verify() reads the signature and nothing else,
        // so the validity period is checked as well.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::expiredResponder();

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $responder->responderIdByName($this->asn1),
            ),
            [$responder->certDer],
            $responder,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/outside its validity period/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseTriesEveryCandidateInTheCertsField(): void
    {
        // certs [0] sits outside tbsResponseData and is covered by no signature, so
        // every candidate is tried. The decoy is a certificate the responder's issuer
        // did not issue, sharing the responder's subject Name so it is tried first.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::responder();

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $responder->responderIdByName($this->asn1),
            ),
            [Authority::ltv()->certDer, $responder->certDer],
            $responder,
        ));

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unparseableBagMemberProvider(): array
    {
        $asn1 = new Asn1();

        $offset = 0;
        $responder = $asn1->readTlv(Authority::responder()->certDer, $offset);

        return [
            'a sequence that is not a certificate' => [$asn1->encodeSequence($asn1->encodeInteger(7))],
            'a certificate carrying appended bytes' => [
                $asn1->encodeSequence($responder['value'] . $asn1->encodeOctetString(\str_repeat('X', 512))),
            ],
        ];
    }

    #[DataProvider('unparseableBagMemberProvider')]
    public function testParseResponseRejectsABagMemberThatIsNotACertificate(string $member): void
    {
        // RFC 6960 section 4.2.1 types certs [0] as SEQUENCE OF Certificate, so a
        // member has to parse as one rather than merely carry the SEQUENCE tag.
        // Unlike a candidate the responder search walks past, this is a member the
        // structure may not have.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::responder();

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $responder->responderIdByName($this->asn1),
            ),
            [$member, $responder->certDer],
            $responder,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP responder certificates/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAcceptsAResponseBehindARolledOverResponderCertificate(): void
    {
        // An authority that has rolled its responder key holds two certificates the
        // ResponderID names equally: same subject Name, same issuer, both carrying
        // OCSPSigning, both in date. Only one holds the key that signed, so the
        // signature is part of the search rather than a step after it.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $responder = Authority::responder();
        $rolled = Authority::rolledResponder();

        // The precondition the case rests on: both certificates answer to the same
        // ResponderID, so the decoy is a candidate rather than something skipped.
        $this->assertSame(
            $this->certificate->fields($responder->certDer)['subject'],
            $this->certificate->fields($rolled->certDer)['subject'],
        );

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $responder->responderIdByName($this->asn1),
            ),
            [$rolled->certDer, $responder->certDer],
            $responder,
        ));

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAResponseNamingTheIssuerThatItDidNotSign(): void
    {
        // The issuer needs no delegation, but it still has to be the key that signed.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData($this->der->singleResponse($request->certId)),
            [],
            Authority::responder(),
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not verify/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseReportsTheRejectionWhenNoCandidateIsAuthorised(): void
    {
        // With no usable candidate left, the first rejection is reported rather than
        // "the response does not carry the responder certificate".
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $leaf = Authority::leaf();

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $leaf->responderIdByName($this->asn1),
            ),
            [$leaf->certDer],
            $leaf,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/lacks the OCSPSigning purpose/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseMatchesTheCertIdByValueNotByEncoding(): void
    {
        // RFC 3279 requires NULL parameters on the SHA-1 AlgorithmIdentifier, but a
        // responder that rebuilds the CertID with them absent names the same
        // certificate, so the comparison is by value.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $offset = 0;
        $certId = $this->asn1->readTlv($request->certId, $offset);
        $inner = 0;
        $this->asn1->readTlv($certId['value'], $inner);
        $rest = \substr($certId['value'], $inner);

        $reEncoded = $this->asn1->encodeSequence(
            $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier('1.3.14.3.2.26')) . $rest,
        );
        $this->assertNotSame($request->certId, $reEncoded);

        $response = $this->der->ocspResponse($reEncoded);
        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    /**
     * CertID structures that are not a CertID.
     *
     * @return array<string, array{callable(Asn1): string}>
     */
    public static function malformedCertIdProvider(): array
    {
        return [
            'not a sequence' => [static fn(Asn1 $asn1): string => $asn1->encodeInteger(1)],
            'algorithm not a sequence' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence($asn1->encodeInteger(1)),
            ],
            'algorithm has no oid' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence(
                    $asn1->encodeSequence($asn1->encodeInteger(1))
                        . $asn1->encodeOctetString('n')
                        . $asn1->encodeOctetString('k')
                        . $asn1->encodeInteger(1),
                ),
            ],
            'hashes not octet strings' => [
                static fn(Asn1 $asn1): string => $asn1->encodeSequence(
                    $asn1->encodeSequence($asn1->encodeObjectIdentifier('1.3.14.3.2.26'))
                        . $asn1->encodeInteger(1)
                        . $asn1->encodeInteger(2)
                        . $asn1->encodeInteger(3),
                ),
            ],
        ];
    }

    /**
     * An entry whose CertID does not parse names no certificate, so it answers
     * nothing about the one asked about and is passed over. With no other entry, the
     * response matches nothing.
     *
     * @param callable(Asn1): string $build
     */
    #[DataProvider('malformedCertIdProvider')]
    public function testParseResponseSkipsAnEntryWithAMalformedCertId(callable $build): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not match the request/');
        $client->parseResponse($this->der->ocspResponse($build($this->asn1)), $request, self::NOW);
    }

    /**
     * A malformed entry ahead of the real one must not discard the whole response.
     *
     * @param callable(Asn1): string $build
     */
    #[DataProvider('malformedCertIdProvider')]
    public function testParseResponseFindsTheAnswerBehindAMalformedEntry(callable $build): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($build($this->asn1)) . $this->der->singleResponse($request->certId),
            )),
        );

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsResponseBytesThatAreNotASequence(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->asn1->encodeSequence(
            $this->der->enumerated(0) . $this->asn1->encodeContext(0, $this->asn1->encodeInteger(1)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP response bytes/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsAResponderIdWithTrailingBytes(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responderId = $this->asn1->encodeContext(
            1,
            Authority::ocsp()->subject($this->asn1) . $this->asn1->encodeInteger(1),
        );
        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId),
                $responderId,
            )),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP responderID/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsANextUpdateThatIsNotAGeneralizedTime(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $single = $this->asn1->encodeSequence(
            $request->certId . "\x80\x00" . $this->der->generalizedTime(self::NOW - 3600)
                . $this->asn1->encodeContext(0, $this->asn1->encodeInteger(1)),
        );
        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse($this->der->responseData($single)));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP nextUpdate/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsACertIdForAnotherSerial(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $other = $client->build($this->caDer, Authority::responder()->certDer);

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not match the request/');
        $client->parseResponse($this->der->ocspResponse($other->certId), $request, self::NOW);
    }

    public function testParseResponseRejectsTrailingBytesAfterTheBasicResponse(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $basic = $this->der->basicResponse($this->der->responseData($this->der->singleResponse($request->certId)));
        $response = $this->der->ocspResponseBytes(0, $basic . $this->asn1->encodeInteger(1));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Trailing bytes/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsARevokedCertificateWithItsOwnType(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // revoked is a verdict rather than a failure to answer, so it carries its
        // own exception type.
        $revoked = $this->asn1->encodeContext(1, $this->der->generalizedTime(self::NOW - 86_400));
        $response = $this->der->ocspResponse($request->certId, $revoked);

        $this->expectException(RevokedException::class);
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAcceptsAResponderIdentifiedByKey(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId),
                Authority::ocsp()->responderIdByKey($this->asn1),
            )),
        );

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAResponderWithoutTheOcspSigningPurpose(): void
    {
        // The leaf is issued by the same CA but carries no OCSPSigning purpose, so
        // the issuer never delegated to it.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $leaf = Authority::leaf();

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $leaf->responderIdByName($this->asn1),
            ),
            [$leaf->certDer],
            $leaf,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/OCSPSigning/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsAResponderTheIssuerDidNotAuthorise(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $stranger = Authority::ltv();

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse(
            $this->der->responseData(
                $this->der->singleResponse($request->certId),
                $stranger->responderIdByName($this->asn1),
            ),
            [$stranger->certDer],
            $stranger,
        ));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/not authorised/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsAnUnknownResponder(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        // Names a responder whose certificate the response does not carry.
        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId),
                $this->asn1->encodeContext(1, $this->asn1->encodeSequence('')),
            )),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not carry the responder certificate/');
        $client->parseResponse($response, $request, self::NOW);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidResponderIdProvider(): array
    {
        return [
            'unsupported choice' => ["\xA3\x02\x30\x00"],
            'byKey without an octet string' => ["\xA2\x03\x02\x01\x01"],
        ];
    }

    #[DataProvider('invalidResponderIdProvider')]
    public function testParseResponseRejectsAnInvalidResponderId(string $responderId): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($request->certId),
                $responderId,
            )),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/responderID/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseFindsAMatchingSingleResponseThatIsNotFirst(): void
    {
        // A responder may answer with several SingleResponse entries in any order.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $other = $client->build($this->caDer, $this->caDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData(
                $this->der->singleResponse($other->certId) . $this->der->singleResponse($request->certId),
            )),
        );

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAnExpiredResponseWithAnOutOfRangeNextUpdate(): void
    {
        // gmmktime() wraps an out-of-range field, so 20219999999999Z would decode
        // to a different, plausible instant.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $next = $this->asn1->encodeContext(0, "\x18\x0F" . '20219999999999Z');
        $single = $this->asn1->encodeSequence(
            $request->certId . "\x80\x00" . $this->der->generalizedTime(Der::RECENT_THIS_UPDATE) . $next,
        );

        $response = $this->der->ocspResponseBytes(0, $this->der->basicResponse($this->der->responseData($single)));

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Out-of-range/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsASingleResponseThatIsNotASequence(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $response = $this->der->ocspResponseBytes(
            0,
            $this->der->basicResponse($this->der->responseData($this->asn1->encodeInteger(1))),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP SingleResponse/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseAcceptsAResponseWithNoCertsField(): void
    {
        // certs [0] is OPTIONAL; a responder signing with the issuer's own key omits it.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);
        $response = $this->der->ocspResponse($request->certId);

        $this->assertSame($response, $client->parseResponse($response, $request, self::NOW));
    }

    public function testParseResponseRejectsAnUnexpectedFieldInPlaceOfCerts(): void
    {
        // certs [0] is the tail field of a BasicOCSPResponse (RFC 6960 section
        // 4.2.1), so an element carrying another tag is refused rather than reported
        // as an absent field.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData($this->der->singleResponse($request->certId));
        $basic = $this->asn1->encodeSequence(
            $responseData
                . $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID))
                . $this->der->bitString(Authority::ocsp()->sign($responseData))
                . $this->asn1->encodeContext(1, \str_repeat('x', 64)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/field after the responder certificates position/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $basic), $request, self::NOW);
    }

    public function testParseResponseRejectsACertIdCarryingAFifthField(): void
    {
        // serialNumber is the last field of a CertID (RFC 6960 section 4.1.1), so
        // nothing may follow it: the four values the reader extracts are what the
        // request is matched against, and section 3.2 rule 1 asks that the response
        // identify the certificate the request asked about.
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $offset = 0;
        $certId = $this->asn1->readTlv($request->certId, $offset);
        $padded = $this->asn1->encodeSequence($certId['value'] . $this->asn1->encodeOctetString(\str_repeat('X', 64)));

        $response = $this->der->ocspResponse($padded);

        // The padded CertID is not the structure the request sent, so no
        // SingleResponse answers it and the response is refused as unmatched.
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/does not match the request/');
        $client->parseResponse($response, $request, self::NOW);
    }

    public function testParseResponseRejectsAMalformedCertsField(): void
    {
        $client = new Client($this->asn1);
        $request = $client->build($this->caDer, $this->leafDer);

        $responseData = $this->der->responseData($this->der->singleResponse($request->certId));
        $basic = $this->asn1->encodeSequence(
            $responseData
                . $this->asn1->encodeSequence($this->asn1->encodeObjectIdentifier(Authority::SIGNATURE_OID))
                . $this->der->bitString(Authority::ocsp()->sign($responseData))
                . $this->asn1->encodeContext(0, $this->asn1->encodeInteger(1)),
        );

        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/Invalid OCSP responder certificates/');
        $client->parseResponse($this->der->ocspResponseBytes(0, $basic), $request, self::NOW);
    }

    /**
     * Rebuild the fixture leaf certificate with a different serialNumber TLV.
     */
    private function certificateWithSerial(string $serialTlv): string
    {
        $offset = 0;
        $cert = $this->asn1->readTlv($this->leafDer, $offset);

        $tbsOffset = 0;
        $tbs = $this->asn1->readTlv($cert['value'], $tbsOffset);
        $rest = \substr($cert['value'], $tbsOffset);

        $inner = 0;
        $version = '';
        if ((\ord($tbs['value'][0]) & 0xE0) === 0xA0) {
            $version = $this->asn1->readTlv($tbs['value'], $inner)['raw'];
        }

        $this->asn1->readTlv($tbs['value'], $inner); // the original serialNumber
        $newTbs = $this->asn1->encodeSequence($version . $serialTlv . \substr($tbs['value'], $inner));

        // Re-signed by the authority that issued the original, build() asking the
        // issuer's key to answer for the leaf. The certificate's own signature
        // AlgorithmIdentifier is reused, so it still matches the one inside the TBS.
        $restOffset = 0;
        $algorithmId = $this->asn1->readTlv($rest, $restOffset);

        return $this->asn1->encodeSequence(
            $newTbs . $algorithmId['raw'] . $this->der->bitString(Authority::ocsp()->sign($newTbs)),
        );
    }

    public function testBuildHashesTheIssuerNameOfTheCertificateBeingChecked(): void
    {
        // The same authority holding the same key, with its Name re-encoded as a
        // PrintableString. RFC 6960 section 4.1.1 asks for the leaf's own issuer
        // field rather than this certificate's subject.
        $reissued = Certificate::pemToDer((string) \file_get_contents(__DIR__ . '/../data/ocsp_ca_printable.pem'));

        $leaf = $this->certificate->fields($this->leafDer);
        $this->assertNotSame(
            $leaf['issuer'],
            $this->certificate->fields($reissued)['subject'],
            'the fixture is only meaningful while the two Names differ',
        );

        $certId = $this->descend((new Client($this->asn1))->build($reissued, $this->leafDer)->der, 5);

        $inner = 0;
        $this->asn1->readTlv($certId['value'], $inner); // hashAlgorithm
        $nameHash = $this->asn1->readTlv($certId['value'], $inner);
        $keyHash = $this->asn1->readTlv($certId['value'], $inner);

        $this->assertSame(\hash('sha1', $leaf['issuer'], true), $nameHash['value']);
        $this->assertSame(
            \hash('sha1', $this->certificate->fields($this->caDer)['public_key'], true),
            $keyHash['value'],
            'the key hash is the issuer certificate\'s own, and the key did not change',
        );
    }

    /**
     * Read the first TLV, then descend into the first child $depth times.
     *
     * @param int<0, max> $depth
     *
     * @return array{tag: int, value: string, raw: string}
     */
    private function descend(string $data, int $depth): array
    {
        $tlv = ['tag' => 0, 'value' => $data, 'raw' => $data];
        for ($i = 0; $i < $depth; ++$i) {
            $offset = 0;
            $tlv = $this->asn1->readTlv($tlv['value'], $offset);
        }

        return $tlv;
    }
}
