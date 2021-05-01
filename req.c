#include <assert.h>
#include <bearssl.h>
#include "x509cert.h"
#include "asn1.h"

size_t
x509cert_encode_req_info(const struct x509cert_req_info *info, unsigned char *buf)
{
	static const unsigned char ver[] = {0x02, 0x01, 0x00};
	static const unsigned char oid_subjectAltName[] = {
		/* OID 2.5.29.17 */
		0x06, 0x03, 0x55, 0x1d, 0x11,
	};
	static const unsigned char oid_extensionRequest[] = {
		/* OID 1.2.840.114549.1.9.14 */
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
	};
	struct asn1_item attrs = {0xa0};
	struct asn1_item cri = {ASN1_SEQUENCE};
	struct asn1_item san = {ASN1_SEQUENCE};
	struct asn1_item data = {ASN1_OCTETSTRING};
	struct asn1_item ext = {ASN1_SEQUENCE};
	struct asn1_item exts = {ASN1_SEQUENCE};
	struct asn1_item vals = {ASN1_SET};
	struct asn1_item attr = {ASN1_SEQUENCE};
	unsigned char *pos;
	size_t len;

	cri.len = x509cert_encode_pkey(&info->pkey, NULL);
	if (!cri.len)
		return 0;
	cri.len += sizeof(ver) + x509cert_encode_dn(&info->name, NULL);

	if (info->alts_len > 0) {
		for (size_t i = 0; i < info->alts_len; ++i)
			san.len += asn1_encode(&info->alts[i], NULL);
		data.len = asn1_encode(&san, NULL);
		ext.len = sizeof(oid_subjectAltName) + asn1_encode(&data, NULL);
		exts.len = asn1_encode(&ext, NULL);
		vals.len = asn1_encode(&exts, NULL);
		attr.len = sizeof(oid_extensionRequest) + asn1_encode(&vals, NULL);
		attrs.len += asn1_encode(&attr, NULL);
	}

	cri.len += asn1_encode(&attrs, NULL);
	len = asn1_encode(&cri, NULL);

	if (!buf)
		return len;

	pos = buf;
	pos += asn1_encode(&cri, pos);
	pos += asn1_copy(ver, pos);
	pos += x509cert_encode_dn(&info->name, pos);
	pos += x509cert_encode_pkey(&info->pkey, pos);
	pos += asn1_encode(&attrs, pos);
	if (info->alts_len > 0) {
		pos += asn1_encode(&attr, pos);
		pos += asn1_copy(oid_extensionRequest, pos);
		pos += asn1_encode(&vals, pos);
		pos += asn1_encode(&exts, pos);
		pos += asn1_encode(&ext, pos);
		pos += asn1_copy(oid_subjectAltName, pos);
		pos += asn1_encode(&data, pos);
		pos += asn1_encode(&san, pos);
		for (size_t i = 0; i < info->alts_len; ++i)
			pos += asn1_encode(&info->alts[i], pos);
	}

	assert(pos - buf == len);
	return len;
}

struct req_info_item {
	struct asn1_item item;
	const struct x509cert_req_info *info;
};

static size_t
encode_cri(const struct asn1_item *item, unsigned char *buf)
{
	struct req_info_item *r = (void *)item;

	return x509cert_encode_req_info(r->info, buf);
}

size_t
x509cert_req(const struct x509cert_req_info *info, const struct x509cert_skey *key, const br_hash_class *hc, unsigned char *buf)
{
	struct req_info_item r = {.item.enc = encode_cri, .info = info};

	return x509cert_sign(&r.item, key, hc, buf);
}
