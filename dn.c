#include <assert.h>
#include "x509cert.h"
#include "inner.h"

static size_t
encode_rdn(const struct x509cert_rdn *rdn, unsigned char *buf)
{
	struct x509cert_item item = {X509CERT_ASN1_SET};
	struct x509cert_item attr = {X509CERT_ASN1_SEQUENCE};
	size_t len;

	attr.len = x509cert_copy(rdn->oid, NULL) + x509cert_encode(&rdn->val, NULL);
	item.len = x509cert_encode(&attr, NULL);
	len = x509cert_encode(&item, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += x509cert_encode(&item, pos);
		pos += x509cert_encode(&attr, pos);
		pos += x509cert_copy(rdn->oid, pos);
		pos += x509cert_encode(&rdn->val, pos);
		assert(pos - buf == len);
	}
	return len;
}

size_t
x509cert_encode_dn(const struct x509cert_dn *dn, unsigned char *buf)
{
	struct x509cert_item item = {X509CERT_ASN1_SEQUENCE};
	size_t len;

	for (size_t i = 0; i < dn->rdn_len; ++i)
		item.len += encode_rdn(&dn->rdn[i], NULL);
	len = x509cert_encode(&item, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += x509cert_encode(&item, buf);
		for (size_t i = 0; i < dn->rdn_len; ++i)
			pos += encode_rdn(&dn->rdn[i], pos);
		assert(pos - buf == len);
	}
	return len;
}

size_t
x509cert_dn_encoder(const struct x509cert_item *item, unsigned char *buf)
{
	return x509cert_encode_dn(item->val, buf);
}
