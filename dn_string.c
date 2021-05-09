#include <ctype.h>
#include "x509cert.h"

#define LEN(a) (sizeof(a) / sizeof((a)[0]))

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
specialchar(int c)
{
	return !!strchr(",=\n+<>#;", c);
}

static inline int
stringchar(int c)
{
	return !specialchar(c) && c != '\\' && c != '"';
}

size_t
x509cert_dn_string_rdn_len(const char *s)
{
	size_t len;
	int quote = 0;

	len = 1;
	for (; *s; ++s) {
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
				++len;
			break;
		}
	}
	return len;
}

int
x509cert_parse_dn_string(struct x509cert_rdn *rdn, const char *str, void *bufptr, size_t len)
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
	const char *s, *end;
	unsigned char *buf = bufptr, *bufend = buf + len;
	int quote = 0;

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
		for (size_t i = 0; i < LEN(keywords); ++i) {
			if (strncmp(keywords[i].key, str, end - str) == 0 && !keywords[i].key[end - str]) {
				rdn->oid = keywords[i].oid;
				break;
			}
		}
		if (!rdn->oid)
			return 0;
		space(&s);
		if (*s != '=')
			return 0;
		++s;
		space(&s);
		rdn->val.val = buf;
		if (*s == '#') {
			return 0;
		} else {
			if (*s == '"') {
				++s;
				quote = 1;
			}
			while (stringchar(*s) || (quote && specialchar(*s)) || *s == '\\') {
				if (*s == '\\')
					++s;
				if (buf == bufend)
					return 0;
				*buf++ = *s++;
			}
			if (quote) {
				if (*s != '"')
					return 0;
				++s;
				quote = 0;
			}
		}
		rdn->val.tag = X509CERT_ASN1_UTF8STRING;
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
		return 0;
	return 1;
}
