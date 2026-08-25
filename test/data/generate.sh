#!/usr/bin/env bash
#
# Regenerate the test certificates in this directory.
#
# The private keys are committed alongside the certificates because the tests
# have to produce genuinely signed OCSP responses and CRLs: the codecs verify
# those signatures, so a fixture that is not really signed proves nothing. The
# keys are throwaway and guard nothing.
#
# Two independent chains are generated. The "ltv" chain carries the AIA and CRL
# distribution point extensions the URL extraction tests read. The "ocsp" chain
# carries none, and adds a delegated responder certificate and a TSA certificate
# so the OCSP responder authorisation and RFC 3161 timestamp paths can be
# exercised, each with an expired counterpart for the negative case.

set -euo pipefail

cd "$(dirname "$0")"

SUBJ_PREFIX="/C=IT/O=Tecnick.com/CN=tc-lib-pdf-sign"
CA_DAYS=7300
LEAF_DAYS=3650

cfg() {
	cat <<-EOF
		[req]
		distinguished_name = dn
		prompt = no
		[dn]
		C = IT
		O = Tecnick.com
		[ca_ext]
		subjectKeyIdentifier = hash
		basicConstraints = critical,CA:TRUE
		keyUsage = critical,keyCertSign,cRLSign
		[leaf_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature,nonRepudiation
		[ltv_leaf_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature,nonRepudiation
		authorityInfoAccess = OCSP;URI:http://ocsp.example.org/r,caIssuers;URI:http://ca.example.org/ca.crt
		crlDistributionPoints = URI:http://crl.example.org/root.crl,URI:http://crl2.example.org/root.crl
		[rollover_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:TRUE
		keyUsage = critical,keyCertSign,cRLSign
		authorityInfoAccess = OCSP;URI:http://ocsp.example.org/r
		crlDistributionPoints = URI:http://crl.example.org/root.crl
		[no_keyid_ext]
		subjectKeyIdentifier = none
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature,nonRepudiation
		[url_injection_ext]
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature
		authorityInfoAccess = caIssuers;URI:http://ca.example/x-OCSP-URI:http://169.254.169.254/meta/
		crlDistributionPoints = url_injection_crldp
		[url_injection_crldp]
		fullname = dirName:url_injection_name
		[url_injection_name]
		CN = URI:http://169.254.169.254/injected
		[responder_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature
		extendedKeyUsage = OCSPSigning
		[tsa_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature,nonRepudiation
		extendedKeyUsage = critical,timeStamping
		[lax_tsa_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature,nonRepudiation
		extendedKeyUsage = timeStamping
		[unsigning_responder_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,keyEncipherment
		extendedKeyUsage = OCSPSigning
		[unsigning_tsa_ext]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,keyEncipherment
		extendedKeyUsage = critical,timeStamping
	EOF
}

CONF="$(mktemp)"
trap 'rm -f "$CONF" ./*.csr' EXIT
cfg >"$CONF"

selfsigned() { # name cn
	openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$CA_DAYS" \
		-keyout "$1.key" -out "$1.pem" -subj "$SUBJ_PREFIX $2" \
		-config "$CONF" -extensions ca_ext
}

issued() { # name cn issuer ext [extra x509 args...]
	openssl req -new -newkey rsa:2048 -nodes -sha256 \
		-keyout "$1.key" -out "$1.csr" -subj "$SUBJ_PREFIX $2" -config "$CONF"
	local name="$1" issuer="$3" ext="$4"
	shift 4
	openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" -CAcreateserial \
		-sha256 -days "$LEAF_DAYS" -out "$name.pem" -extfile "$CONF" -extensions "$ext" "$@"
}

selfsigned ltv_ca "ltv CA"
issued ltv_cert "ltv" ltv_ca ltv_leaf_ext

# A CA key rollover certificate: the ltv CA's own subject Name, the ltv CA as its
# issuer, and a new key, signed by the key the CA holds now. RFC 5280 calls that
# self-issued, which is not the same as self-signed, and the difference is what
# separates a trust anchor whose own revocation material says nothing useful from
# an ordinary CA certificate whose does. It carries an AIA and a distribution
# point so there is something to consult, and to report when nothing consults it.
issued ltv_rollover "ltv CA" ltv_ca rollover_ext

selfsigned ocsp_ca "root CA"
issued ocsp_leaf "leaf" ocsp_ca leaf_ext
issued ocsp_responder "OCSP responder" ocsp_ca responder_ext

# A leaf with no subjectKeyIdentifier extension. RFC 5280 section 4.2.1.2 only
# recommends the extension, so a SignerInfo naming its signer by
# subjectKeyIdentifier has to be resolved against a bag that may hold a
# certificate carrying none, and the empty identifier that stands for its absence
# must not match the empty one a malformed SignerIdentifier would carry.
# "subjectKeyIdentifier = none" is needed because openssl x509 adds the extension
# by default when the extension section does not mention it.
issued ocsp_no_keyid "no key id leaf" ocsp_ca no_keyid_ext

# A leaf whose extensions carry no OCSP responder and no distribution point URI,
# but whose caIssuers URI and whose CRL distribution point directoryName both hold
# text shaped like one. A reader that searches OpenSSL's rendering of an extension
# rather than decoding its DER answers with the embedded strings, so this is the
# certificate that says which of the two the URL extraction does.
issued ocsp_url_injection "URL injection leaf" ocsp_ca url_injection_ext

# The same authority, holding the same key, with its Name carried as a
# PrintableString where ocsp_ca carries the UTF8String of the current OpenSSL
# default. It is what a CA that re-issues its own certificate under another
# string mask looks like: the leaves it signed still name it as it was encoded
# then, so the two Names have the same value and different octets, and only the
# signature links them. No key is written, since it is ocsp_ca's own.
MASK_CONF="$(mktemp)"
{
	echo '[req]'
	echo 'string_mask = nombstr'
	cfg | tail -n +2
} >"$MASK_CONF"
openssl req -x509 -key ocsp_ca.key -sha256 -days "$CA_DAYS" -out ocsp_ca_printable.pem \
	-subj "$SUBJ_PREFIX root CA" -config "$MASK_CONF" -extensions ca_ext
rm -f "$MASK_CONF"

# A responder whose certificate has expired. RFC 6960 section 3.2 rule 4 asks for a
# responder that is currently authorised, and openssl_x509_verify() reads only the
# signature, so the negative case needs a certificate outside its validity period.
issued ocsp_expired_responder "expired OCSP responder" ocsp_ca responder_ext \
	-not_before 20100101000000Z -not_after 20210101000000Z

# An authority that has rolled its responder key holds two certificates with the
# same subject Name, both issued by it, both carrying OCSPSigning, both inside
# their validity period, and only one of them holding the key that signed a given
# response. The retired one is public, so the codec has to try every candidate the
# unauthenticated certs [0] bag names rather than stopping at the first authorised
# one. Same CN and config as ocsp_responder, so the two subject Names are the same
# octets and the ResponderID matches both.
issued ocsp_rolled_responder "OCSP responder" ocsp_ca responder_ext

# RFC 3161 section 2.3 reserves a TSA key for timestamping alone, so the codec
# refuses a token signed by anything else. The certificate has to cover the
# instant the token attests, which a signature check alone does not establish,
# so both a valid and an expired one are needed. The valid window is stated
# rather than counted from today because the timestamp tests pin genTime to a
# fixed instant, which a window starting at the moment of generation misses.
issued ocsp_tsa "TSA" ocsp_ca tsa_ext \
	-not_before 20200101000000Z -not_after 20400101000000Z
issued ocsp_expired_tsa "expired TSA" ocsp_ca tsa_ext \
	-not_before 20100101000000Z -not_after 20210101000000Z

# The same section requires the extension to be critical. An extension the issuer
# did not mark critical is one a reader is free to ignore, and a purpose no reader
# has to honour is not the reservation the rule is about, so the negative case
# needs a TSA carrying the purpose without the flag.
issued ocsp_lax_tsa "lax TSA" ocsp_ca lax_tsa_ext \
	-not_before 20200101000000Z -not_after 20400101000000Z

# RFC 5280 section 4.2.1.3 reserves digitalSignature for a signature that is not
# over a certificate or a CRL, which is what an OCSP response and a timestamp
# token each carry. A certificate stating the purpose its gate demands while its
# critical keyUsage forbids signing at all is the case that says whether both
# statements the issuer made are read, so each gate gets one.
issued ocsp_unsigning_responder "unsigning OCSP responder" ocsp_ca unsigning_responder_ext
issued ocsp_unsigning_tsa "unsigning TSA" ocsp_ca unsigning_tsa_ext \
	-not_before 20200101000000Z -not_after 20400101000000Z

rm -f ./*.srl

openssl verify -CAfile ltv_ca.pem ltv_cert.pem
openssl verify -CAfile ltv_ca.pem ltv_rollover.pem
openssl verify -CAfile ocsp_ca.pem ocsp_leaf.pem
openssl verify -purpose ocsphelper -CAfile ocsp_ca.pem ocsp_responder.pem
openssl verify -purpose ocsphelper -CAfile ocsp_ca.pem ocsp_rolled_responder.pem
openssl verify -purpose timestampsign -CAfile ocsp_ca.pem ocsp_tsa.pem
openssl x509 -in ocsp_expired_responder.pem -noout -dates
openssl x509 -in ocsp_expired_tsa.pem -noout -dates
