#include <assert.h>
#include "x509cert.h"
#include "inner.h"

size_t
x509cert_encode_san(const struct x509cert_item *alts, size_t n, unsigned char *buf)
{
	static const unsigned char oid[] = {
		/* OID 2.5.29.17 - subjectAltName */
		0x06, 0x03, 0x55, 0x1d, 0x11,
	};
	struct x509cert_item ext = {X509CERT_ASN1_SEQUENCE};
	struct x509cert_item data = {X509CERT_ASN1_OCTETSTRING};
	struct x509cert_item san = {X509CERT_ASN1_SEQUENCE};
	size_t len;

	for (size_t i = 0; i < n; ++i)
		san.len += x509cert_encode(&alts[i], NULL);
	data.len = x509cert_encode(&san, NULL);
	ext.len = sizeof(oid) + x509cert_encode(&data, NULL);
	len = x509cert_encode(&ext, NULL);

	if (buf) {
		unsigned char *pos = buf;
		pos += x509cert_encode(&ext, pos);
		pos += x509cert_copy(oid, pos);
		pos += x509cert_encode(&data, pos);
		pos += x509cert_encode(&san, pos);
		for (size_t i = 0; i < n; ++i)
			pos += x509cert_encode(&alts[i], pos);
		assert(pos - buf == len);
	}

	return len;
}
