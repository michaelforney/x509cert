#include <assert.h>
#include <stdio.h>
#include "x509cert.h"

static size_t
encode_tm(const struct tm *tm, unsigned char *buf)
{
	static const char dec[] = "0123456789";
	char str[16];
	struct asn1_item item = {ASN1_GENERALIZEDTIME, 15, str};
	int x;

	if (buf) {
		x = tm->tm_year;
		str[3] = dec[x % 10], x /= 10;
		str[2] = dec[x % 10], x = x / 10 + 19;
		str[1] = dec[x % 10], x /= 10;
		str[0] = dec[x % 10];
		x = tm->tm_mon + 1;
		str[5] = dec[x % 10], x /= 10;
		str[4] = dec[x % 10];
		x = tm->tm_mday;
		str[7] = dec[x % 10], x /= 10;
		str[6] = dec[x % 10];
		x = tm->tm_hour;
		str[9] = dec[x % 10], x /= 10;
		str[8] = dec[x % 10];
		x = tm->tm_min;
		str[11] = dec[x % 10], x /= 10;
		str[10] = dec[x % 10];
		x = tm->tm_sec;
		str[13] = dec[x % 10], x /= 10;
		str[12] = dec[x % 10];
		str[14] = 'Z';
		str[15] = '\0';
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
