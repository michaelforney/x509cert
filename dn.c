#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
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

static inline void
space(const char **str)
{
	const char *s = *str;

	if (*s == '\n')
		++s;
	while (*s == ' ')
		++s;
	*str = s;
}

static inline int
isspecial(int c)
{
	return !!strchr(",=\n+<>#;", c);
}

static inline int
isstringchar(int c)
{
	return !isspecial(c) && c != '\\' && c != '"';
}

int
x509cert_parse_dn_string(struct x509cert_dn *dn, const char *str, unsigned char *buf, size_t len)
{
	static const struct {
		char key[7];
		unsigned char oid[5];
	} keywords[] = {
		{"CN",     {0x06, 0x03, 0x55, 0x04, 0x03}}, /* 2.5.4.3 */
		{"L",      {0x06, 0x03, 0x55, 0x04, 0x07}}, /* 2.5.4.7 */
		{"ST",     {0x06, 0x03, 0x55, 0x04, 0x08}}, /* 2.5.4.8 */
		{"O",      {0x06, 0x03, 0x55, 0x04, 0x0a}}, /* 2.5.4.10 */
		{"OU",     {0x06, 0x03, 0x55, 0x04, 0x0b}}, /* 2.5.4.11 */
		{"C",      {0x06, 0x03, 0x55, 0x04, 0x06}}, /* 2.5.4.6 */
		{"STREET", {0x06, 0x03, 0x55, 0x04, 0x09}}, /* 2.5.4.9 */
	};
	struct x509cert_rdn *rdn;
	const char *s, *end;
	unsigned char *bufend = buf + len;
	int quote = 0;

	/* determine number of components */
	dn->rdn_len = 1;
	for (s = str; *s; ++s) {
		switch (*s) {
		case '"':
			quote ^= 1;
			break;
		case '\\':
			if (s[1])
				++s;
			break;
		case ',':
		case ';':
			if (!quote)
				++dn->rdn_len;
			break;
		}
	}

	rdn = calloc(dn->rdn_len, sizeof(dn->rdn[0]));
	if (!rdn)
		return -1;

	dn->rdn = rdn;

	s = str;
	do {
		str = end = s;
		while (isalnum(*s)) {
			do ++s;
			while (isalnum(*s));
			end = s;
			while (*s == ' ')
				++s;
		}
		for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); ++i) {
			if (strncmp(keywords[i].key, str, end - str) == 0 && !keywords[i].key[end - str]) {
				rdn->oid = keywords[i].oid;
				break;
			}
		}
		if (!rdn->oid)
			return -1;
		space(&s);
		if (*s != '=')
			return -1;
		++s;
		space(&s);
		rdn->val.val = buf;
		if (*s == '#') {
			return -1;
		} else {
			if (*s == '"') {
				++s;
				quote = 1;
			}
			while (isstringchar(*s) || (quote && isspecial(*s))) {
				if (*s == '\\')
					++s;
				if (buf == bufend)
					return -1;
				*buf++ = *s++;
			}
			if (quote) {
				if (*s != '"')
					return -1;
				++s;
			}
		}
		rdn->val.tag = ASN1_IA5STRING;
		rdn->val.len = buf - rdn->val.val;
		space(&s);
		/* multi-valued RDNs are not supported; assume no '+' */
		if (*s != ',' && *s != ';')
			break;
		++s;
		space(&s);
		++rdn;
	} while (*s);
	if (*s)
		return -1;
	return 0;
}
