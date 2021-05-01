#include "x509cert.h"

size_t
x509cert_sign(const struct asn1_item *data, const struct x509cert_skey *key, const br_hash_class *hc, unsigned char *buf)
{
	static const unsigned char oid_ecdsa_sha256[] = {
		/* OID 1.2.840.10045.4.3.2 */
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
	};
	static const unsigned char oid_rsa_sha256[] = {
		/* OID 1.2.840.113549.1.1.11 */
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
	};
	static const unsigned char oid_secp256r1[] = {
		/* OID 1.2.840.10045.3.1.7 - secp384r1 */
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	};
	static const unsigned char oid_secp384r1[] = {
		/* OID 1.3.132.0.34 - secp384r1 */
		0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
	};
	static const unsigned char null[] = {0x05, 0x00};
	struct asn1_item alg = {ASN1_SEQUENCE};
	struct asn1_item sig = {ASN1_BITSTRING};
	struct asn1_item item = {ASN1_SEQUENCE};
	const unsigned char *oid, *hashoid, *params;
	unsigned char *pos, *sigpos, *datapos, *newdatapos;
	unsigned char hash[64];
	size_t len, hashlen, sigmax;
	br_hash_compat_context ctx;
	const br_ec_impl *ec;

	switch (key->type) {
	case BR_KEYTYPE_RSA:
		switch (hc->desc >> BR_HASHDESC_ID_OFF & BR_HASHDESC_ID_MASK) {
		case br_sha256_ID: oid = oid_rsa_sha256, hashoid = BR_HASH_OID_SHA256; break;
		}
		params = null;
		sigmax = (key->u.rsa->n_bitlen + 7) / 8;
		break;
	case BR_KEYTYPE_EC:
		switch (hc->desc >> BR_HASHDESC_ID_OFF & BR_HASHDESC_ID_MASK) {
		case br_sha256_ID: oid = oid_ecdsa_sha256; break;
		}
		/* assume maximum length until we compute the signature */
		switch (key->u.ec->curve) {
		case BR_EC_secp256r1: params = oid_secp256r1, sigmax = 72; break;
		case BR_EC_secp384r1: params = oid_secp384r1, sigmax = 104; break;
		default: return 0;
		}
		break;
	default:
		return 0;
	}

	alg.len = asn1_copy(oid, NULL) + asn1_copy(params, NULL);
	sig.len = ++sigmax;
	item.len = asn1_encode(data, NULL);
	if (item.len == 0)
		return 0;
	item.len += asn1_encode(&alg, NULL) + asn1_encode(&sig, NULL);
	len = asn1_encode(&item, NULL);

	if (!buf)
		return len;

	pos = buf;
	pos += asn1_encode(&item, pos);
	datapos = pos;
	pos += asn1_encode(data, pos);

	hc->init(&ctx.vtable);
	hc->update(&ctx.vtable, datapos, pos - datapos);
	hc->out(&ctx.vtable, hash);
	hashlen = hc->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;

	pos += asn1_encode(&alg, pos);
	pos += asn1_copy(oid, pos);
	pos += asn1_copy(params, pos);

	sigpos = pos;
	pos += asn1_encode(&sig, pos);
	*pos = 0;
	switch (key->type) {
	case BR_KEYTYPE_RSA:
		if (br_rsa_pkcs1_sign_get_default()(hashoid, hash, hashlen, key->u.rsa, pos + 1) != 1)
			return 0;
		break;
	case BR_KEYTYPE_EC:
		ec = br_ec_get_default();
		sig.len = br_ecdsa_sign_asn1_get_default()(ec, hc, hash, key->u.ec, pos + 1);
		if (sig.len == 0)
			return 0;
		++sig.len;
		/*
		 * Re-encode the signature SEQUENCE header with the
		 * correct length. Since the maximum length is <128,
		 * we know the length of the length remains constant.
		 *
		 * XXX: This is not necessarily true for secp521r1
		 * signatures. If support for those is added, we'll
		 * need a temporary signature buffer.
		 */
		asn1_encode(&sig, sigpos);
		break;
	}
	pos += sig.len;

	/*
	 * If the length of the outer SEQUENCE length changed due
	 * to the encoding of the actual signature, move the inner
	 * data into the correct position.
	 */

	item.len -= sigmax - sig.len;
	newdatapos = buf + asn1_encode(&item, buf);
	memmove(newdatapos, datapos, pos - datapos);

	return (newdatapos - buf) + (pos - datapos);
}

