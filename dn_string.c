#include <ctype.h>
#include <stdlib.h>
#include "x509cert.h"

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
x509cert_parse_dn_string(struct x509cert_dn *dn, const char *str, void *bufptr, size_t len)
{
	static const struct {
		char key[7];
		const unsigned char *oid;
	} keywords[] = {
		{"CN",     x509cert_oid_CN},
		{"L",      x509cert_oid_L},
		{"ST",     x509cert_oid_ST},
		{"O",      x509cert_oid_O},
		{"OU",     x509cert_oid_OU},
		{"C",      x509cert_oid_C},
		{"STREET", x509cert_oid_STREET},
	};
	struct x509cert_rdn *rdn;
	const char *s, *end;
	unsigned char *buf = bufptr, *bufend = buf + len;
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
		rdn->val.tag = ASN1_UTF8STRING;
		rdn->val.len = buf - (unsigned char *)rdn->val.val;
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
