#include <assert.h>
#include <bearssl.h>
#include "x509cert.h"
#include "inner.h"

size_t
x509cert_encode_req(const struct x509cert_req *req, unsigned char *buf)
{
	static const unsigned char ver[] = {0x02, 0x01, 0x00};
	static const unsigned char oid_extensionRequest[] = {
		/* OID 1.2.840.114549.1.9.14 */
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
	};
	struct x509cert_item attrs = {0xa0};
	struct x509cert_item cri = {X509CERT_ASN1_SEQUENCE};
	struct x509cert_item attr = {X509CERT_ASN1_SEQUENCE};
	struct x509cert_item vals = {X509CERT_ASN1_SET};
	struct x509cert_item exts = {X509CERT_ASN1_SEQUENCE};
	unsigned char *pos;
	size_t len;

	cri.len = x509cert_encode_pkey(&req->pkey, NULL);
	if (!cri.len)
		return 0;
	cri.len += sizeof(ver) + x509cert_encode(&req->subject, NULL);

	if (req->alts_len > 0) {
		exts.len = x509cert_encode_san(req->alts, req->alts_len, NULL);
		vals.len = x509cert_encode(&exts, NULL);
		attr.len = sizeof(oid_extensionRequest) + x509cert_encode(&vals, NULL);
		attrs.len += x509cert_encode(&attr, NULL);
	}

	cri.len += x509cert_encode(&attrs, NULL);
	len = x509cert_encode(&cri, NULL);

	if (!buf)
		return len;

	pos = buf;
	pos += x509cert_encode(&cri, pos);
	pos += x509cert_copy(ver, pos);
	pos += x509cert_encode(&req->subject, pos);
	pos += x509cert_encode_pkey(&req->pkey, pos);
	pos += x509cert_encode(&attrs, pos);
	if (req->alts_len > 0) {
		pos += x509cert_encode(&attr, pos);
		pos += x509cert_copy(oid_extensionRequest, pos);
		pos += x509cert_encode(&vals, pos);
		pos += x509cert_encode(&exts, pos);
		pos += x509cert_encode_san(req->alts, req->alts_len, pos);
	}

	assert(pos - buf == len);
	return len;
}

size_t
x509cert_req_encoder(const struct x509cert_item *item, unsigned char *buf)
{
	return x509cert_encode_req(item->val, buf);
}
