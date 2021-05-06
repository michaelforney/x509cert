#include <assert.h>
#include <bearssl.h>
#include "asn1.h"
#include "x509cert.h"

static size_t
encode_rsa(const br_rsa_public_key *pk, unsigned char *buf)
{
	static const unsigned char alg[] = {
		0x30, 0x0d,
		/* OID 1.2.840.113549.1.1.1 - rsaEncryption */
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		/* NULL parameters */
		0x05, 0x00,
	};
	struct asn1_item item = {ASN1_SEQUENCE};
	struct asn1_item key = {ASN1_BITSTRING};
	struct asn1_item rsa = {ASN1_SEQUENCE};
	struct asn1_item n, e;
	size_t len;

	asn1_uint(&n, pk->n, pk->nlen);
	asn1_uint(&e, pk->e, pk->elen);
	rsa.len = asn1_encode(&n, NULL) + asn1_encode(&e, NULL);
	key.len = 1 + asn1_encode(&rsa, NULL);
	item.len = sizeof(alg) + asn1_encode(&key, NULL);
	len = asn1_encode(&item, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += asn1_encode(&item, pos);
		pos += asn1_copy(alg, pos);
		pos += asn1_encode(&key, pos);
		*pos++ = 0;
		pos += asn1_encode(&rsa, pos);
		pos += asn1_encode(&n, pos);
		pos += asn1_encode(&e, pos);
		assert(pos - buf == len);
	}
	return len;
}

static size_t
encode_ec(const br_ec_public_key *pk, unsigned char *buf)
{
	static const unsigned char oid[] = {
		/* OID 1.2.840.10045.2.1 - id-ecPublicKey */
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	};
	static const unsigned char oid_secp256r1[] = {
		/* OID 1.2.840.10045.3.1.7 - secp256r1 */
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	};
	static const unsigned char oid_secp384r1[] = {
		/* OID 1.3.132.0.34 - secp384r1 */
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
	};
	static const unsigned char oid_secp521r1[] = {
		/* OID 1.3.132.0.34 - secp521r1 */
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
	};
	struct asn1_item item = {ASN1_SEQUENCE};
	struct asn1_item alg = {ASN1_SEQUENCE};
	struct asn1_item key = {ASN1_BITSTRING};
	const unsigned char *curve;
	size_t len;

	switch (pk->curve) {
	case BR_EC_secp256r1: curve = oid_secp256r1; break;
	case BR_EC_secp384r1: curve = oid_secp384r1; break;
	case BR_EC_secp521r1: curve = oid_secp521r1; break;
	default: return 0;
	}
	alg.len = sizeof(oid) + asn1_copy(curve, NULL);
	key.len = 1 + pk->qlen;
	item.len = asn1_encode(&alg, NULL) + asn1_encode(&key, NULL);
	len = asn1_encode(&item, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += asn1_encode(&item, pos);
		pos += asn1_encode(&alg, pos);
		pos += asn1_copy(oid, pos);
		pos += asn1_copy(curve, pos);
		pos += asn1_encode(&key, pos);
		*pos++ = 0;
		memcpy(pos, pk->q, pk->qlen);
		pos += pk->qlen;
		assert(pos - buf == len);
	}
	return len;
}

size_t
x509cert_encode_pkey(const br_x509_pkey *pk, unsigned char *buf)
{
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA: return encode_rsa(&pk->key.rsa, buf);
	case BR_KEYTYPE_EC: return encode_ec(&pk->key.ec, buf);
	}
	return 0;
}
