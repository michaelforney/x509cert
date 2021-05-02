#include <assert.h>
#include "x509cert.h"

size_t
x509cert_encode_san(const struct asn1_item *alts, size_t n, unsigned char *buf)
{
	static const unsigned char oid[] = {
		/* OID 2.5.29.17 - subjectAltName */
		0x06, 0x03, 0x55, 0x1d, 0x11,
	};
	struct asn1_item ext = {ASN1_SEQUENCE};
	struct asn1_item data = {ASN1_OCTETSTRING};
	struct asn1_item san = {ASN1_SEQUENCE};
	size_t len;

	for (size_t i = 0; i < n; ++i)
		san.len += asn1_encode(&alts[i], NULL);
	data.len = asn1_encode(&san, NULL);
	ext.len = sizeof(oid) + asn1_encode(&data, NULL);
	len = asn1_encode(&ext, NULL);

	if (buf) {
		unsigned char *pos = buf;
		pos += asn1_encode(&ext, pos);
		pos += asn1_copy(oid, pos);
		pos += asn1_encode(&data, pos);
		pos += asn1_encode(&san, pos);
		for (size_t i = 0; i < n; ++i)
			pos += asn1_encode(&alts[i], pos);
		assert(pos - buf == len);
	}

	return len;
}
