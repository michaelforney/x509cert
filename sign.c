#include <assert.h>
#include "x509cert.h"

size_t
x509cert_encode_sign_alg(int key, int hash, unsigned char *buf)
{
	static const unsigned char oid_ecdsa_sha256[] = {
		/* OID 1.2.840.10045.4.3.2 */
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
	};
	static const unsigned char oid_rsa_sha256[] = {
		/* OID 1.2.840.113549.1.1.11 */
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
	};
	static const unsigned char null[] = {0x05, 0x00};
	struct x509cert_item alg = {X509CERT_ASN1_SEQUENCE};
	const unsigned char *oid = NULL, *params;
	size_t len;

	switch (key) {
	case BR_KEYTYPE_RSA:
		switch (hash) {
		case br_sha256_ID: oid = oid_rsa_sha256; break;
		}
		params = null;
		break;
	case BR_KEYTYPE_EC:
		switch (hash) {
		case br_sha256_ID: oid = oid_ecdsa_sha256; break;
		}
		params = NULL;
		break;
	}
	if (!oid)
		return 0;
	alg.len = x509cert_copy(oid, NULL);
	if (params)
		alg.len += x509cert_copy(params, NULL);
	len = x509cert_encode(&alg, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += x509cert_encode(&alg, pos);
		pos += x509cert_copy(oid, pos);
		if (params)
			pos += x509cert_copy(params, pos);
		assert(pos - buf == len);
	}
	return len;
}

size_t
x509cert_sign(const struct x509cert_item *data, const struct x509cert_skey *key, const br_hash_class *hc, unsigned char *buf)
{
	struct x509cert_item sig = {X509CERT_ASN1_BITSTRING};
	struct x509cert_item item = {X509CERT_ASN1_SEQUENCE};
	const unsigned char *oid;
	unsigned char *pos, *sigpos, *datapos, *newdatapos;
	unsigned char hash[64];
	int hashid;
	size_t hashlen, sigmax = 0;
	br_hash_compat_context ctx;
	const br_ec_impl *ec;

	hashid = hc->desc >> BR_HASHDESC_ID_OFF & BR_HASHDESC_ID_MASK;
	hashlen = hc->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
	switch (key->type) {
	case BR_KEYTYPE_RSA:
		switch (hashid) {
		case br_sha256_ID: oid = BR_HASH_OID_SHA256; break;
		default: return 0;
		}
		sigmax = (key->u.rsa->n_bitlen + 7) / 8;
		break;
	case BR_KEYTYPE_EC:
		/* assume maximum length until we compute the signature */
		switch (key->u.ec->curve) {
		case BR_EC_secp256r1: sigmax = 72; break;
		case BR_EC_secp384r1: sigmax = 104; break;
		}
		break;
	}
	if (!sigmax)
		return 0;

	sig.len = ++sigmax;
	item.len = x509cert_encode(data, NULL);
	if (item.len == 0)
		return 0;
	item.len += x509cert_encode_sign_alg(key->type, hashid, NULL) + x509cert_encode(&sig, NULL);

	if (!buf)
		return x509cert_encode(&item, NULL);

	pos = buf;
	pos += x509cert_encode(&item, pos);
	datapos = pos;
	pos += x509cert_encode(data, pos);

	hc->init(&ctx.vtable);
	hc->update(&ctx.vtable, datapos, pos - datapos);
	hc->out(&ctx.vtable, hash);

	pos += x509cert_encode_sign_alg(key->type, hashid, pos);
	sigpos = pos;
	pos += x509cert_encode(&sig, pos);
	*pos = 0;
	switch (key->type) {
	case BR_KEYTYPE_RSA:
		if (br_rsa_pkcs1_sign_get_default()(oid, hash, hashlen, key->u.rsa, pos + 1) != 1)
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
		x509cert_encode(&sig, sigpos);
		break;
	}
	pos += sig.len;

	/*
	 * If the length of the outer SEQUENCE length changed due
	 * to the encoding of the actual signature, move the inner
	 * data into the correct position.
	 */
	item.len -= sigmax - sig.len;
	newdatapos = buf + x509cert_encode(&item, buf);
	memmove(newdatapos, datapos, pos - datapos);

	return (newdatapos - buf) + (pos - datapos);
}
