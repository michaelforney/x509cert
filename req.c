#include <assert.h>
#include <bearssl.h>
#include "x509cert.h"
#include "asn1.h"

size_t
x509cert_encode_req(const struct x509cert_req *req, unsigned char *buf)
{
	static const unsigned char ver[] = {0x02, 0x01, 0x00};
	static const unsigned char oid_extensionRequest[] = {
		/* OID 1.2.840.114549.1.9.14 */
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
	};
	struct asn1_item attrs = {0xa0};
	struct asn1_item cri = {ASN1_SEQUENCE};
	struct asn1_item attr = {ASN1_SEQUENCE};
	struct asn1_item vals = {ASN1_SET};
	struct asn1_item exts = {ASN1_SEQUENCE};
	unsigned char *pos;
	size_t len;

	cri.len = x509cert_encode_pkey(&req->pkey, NULL);
	if (!cri.len)
		return 0;
	cri.len += sizeof(ver) + asn1_encode(&req->subject, NULL);

	if (req->alts_len > 0) {
		exts.len = x509cert_encode_san(req->alts, req->alts_len, NULL);
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
	pos += asn1_encode(&req->subject, pos);
	pos += x509cert_encode_pkey(&req->pkey, pos);
	pos += asn1_encode(&attrs, pos);
	if (req->alts_len > 0) {
		pos += asn1_encode(&attr, pos);
		pos += asn1_copy(oid_extensionRequest, pos);
		pos += asn1_encode(&vals, pos);
		pos += asn1_encode(&exts, pos);
		pos += x509cert_encode_san(req->alts, req->alts_len, pos);
	}

	assert(pos - buf == len);
	return len;
}

size_t
x509cert_req_encoder(const struct asn1_item *item, unsigned char *buf)
{
	return x509cert_encode_req(item->val, buf);
}
