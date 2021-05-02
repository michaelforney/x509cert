#include <assert.h>
#include "asn1.h"
#include "x509cert.h"

size_t
x509cert_encode_rdn(const struct x509cert_rdn *rdn, unsigned char *buf)
{
	struct asn1_item item = {ASN1_SET};
	struct asn1_item attr = {ASN1_SEQUENCE};
	size_t len;

	attr.len = asn1_copy(rdn->oid, NULL) + asn1_encode(&rdn->val, NULL);
	item.len = asn1_encode(&attr, NULL);
	len = asn1_encode(&item, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += asn1_encode(&item, pos);
		pos += asn1_encode(&attr, pos);
		pos += asn1_copy(rdn->oid, pos);
		pos += asn1_encode(&rdn->val, pos);
		assert(pos - buf == len);
	}
	return len;
}

size_t
x509cert_encode_dn(const struct x509cert_dn *dn, unsigned char *buf)
{
	struct asn1_item item = {ASN1_SEQUENCE};
	size_t len;

	for (size_t i = 0; i < dn->rdn_len; ++i)
		item.len += x509cert_encode_rdn(&dn->rdn[i], NULL);
	len = asn1_encode(&item, NULL);
	if (buf) {
		unsigned char *pos = buf;
		pos += asn1_encode(&item, buf);
		for (size_t i = 0; i < dn->rdn_len; ++i)
			pos += x509cert_encode_rdn(&dn->rdn[i], pos);
		assert(pos - buf == len);
	}
	return len;
}
