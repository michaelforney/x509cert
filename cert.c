#include <assert.h>
#include <stdio.h>
#include "x509cert.h"

static size_t
encode_tm(const struct tm *tm, unsigned char *buf)
{
	char str[16];
	struct asn1_item item = {ASN1_GENERALIZEDTIME, 15, str};

	if (buf) {
		snprintf(str, sizeof(str), "%04d%02d%02d%02d%02d%02dZ",
			(1900 + tm->tm_year) % 10000, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
	}
	return asn1_encode(&item, buf);
}

/* basicConstraints extension */
static size_t
encode_bc(int ca, unsigned char *buf)
{
	static const unsigned char der[] = {
		0x30, 0x0c,
		0x06, 0x03, 0x55, 0x1d, 0x13,
		0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
	};

	if (buf) {
		memcpy(buf, der, sizeof(der));
		buf[sizeof(der)] = ca ? 0xff : 0;
	}
	return sizeof(der) + 1;
}

size_t
x509cert_encode_cert(const struct x509cert_cert *cert, unsigned char *buf)
{
	static const unsigned char ver[] = {0xa0, 0x03, 0x02, 0x01, 0x02};
	struct asn1_item item = {ASN1_SEQUENCE};
	struct asn1_item validity = {ASN1_SEQUENCE};
	struct asn1_item optexts = {0xa3};
	struct asn1_item exts = {ASN1_SEQUENCE};
	size_t len;

	item.len += asn1_encode_uint(&cert->serial, NULL);
	len = x509cert_encode_sign_alg(cert->alg.type, cert->alg.hash, NULL);
	if (len == 0)
		return 0;
	item.len += len;
	item.len += asn1_encode(&cert->issuer, NULL);
	validity.len = encode_tm(NULL, NULL) + encode_tm(NULL, NULL);
	item.len += asn1_encode(&validity, NULL);
	item.len += asn1_encode(&cert->req->subject, NULL);
	item.len += x509cert_encode_pkey(&cert->req->pkey, NULL);
	if (cert->req->alts_len > 0)
		exts.len += x509cert_encode_san(cert->req->alts, cert->req->alts_len, NULL);
	if (cert->ca)
		exts.len += encode_bc(cert->ca, NULL);
	if (exts.len > 0) {
		item.len += sizeof(ver);
		optexts.len = asn1_encode(&exts, NULL);
		item.len += asn1_encode(&optexts, NULL);
	}
	len = asn1_encode(&item, NULL);

	if (buf) {
		struct tm *tm;
		unsigned char *pos = buf;

		pos += asn1_encode(&item, pos);
		if (exts.len > 0)
			pos += asn1_copy(ver, pos);
		pos += asn1_encode_uint(&cert->serial, pos);
		pos += x509cert_encode_sign_alg(cert->alg.type, cert->alg.hash, pos);
		pos += asn1_encode(&cert->issuer, pos);
		pos += asn1_encode(&validity, pos);
		if (!(tm = gmtime(&cert->notbefore)))
			return 0;
		pos += encode_tm(tm, pos);
		if (!(tm = gmtime(&cert->notafter)))
			return 0;
		pos += encode_tm(tm, pos);
		pos += asn1_encode(&cert->req->subject, pos);
		pos += x509cert_encode_pkey(&cert->req->pkey, pos);
		if (exts.len > 0) {
			pos += asn1_encode(&optexts, pos);
			pos += asn1_encode(&exts, pos);
			if (cert->req->alts_len > 0)
				pos += x509cert_encode_san(cert->req->alts, cert->req->alts_len, pos);
			if (cert->ca)
				pos += encode_bc(cert->ca, pos);
		}
		assert(pos - buf == len);
	}

	return len;
}

size_t
x509cert_cert_encoder(const struct asn1_item *item, unsigned char *buf)
{
	return x509cert_encode_cert(item->val, buf);
}
