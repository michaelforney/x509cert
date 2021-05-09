#include <ctype.h>
#include "x509cert.h"

#define LEN(a) (sizeof(a) / sizeof((a)[0]))

size_t
x509cert_dn_string_rdn_len(const char *s)
{
	size_t len;

	len = 1;
	for (; *s; ++s) {
		switch (*s) {
		case '\\': if (s[1]) ++s; break;
		case ',': ++len; break;
		}
	}
	return len;
}

static const unsigned char *
keyword(const char *str, size_t len)
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
		{"DC",     x509cert_oid_DC},
		{"UID",    x509cert_oid_UID},
	};

	for (size_t i = 0; i < LEN(keywords); ++i) {
		if (strncmp(keywords[i].key, str, len) == 0 && !keywords[i].key[len])
			return keywords[i].oid;
	}
	return NULL;
}

static int
hexval(int c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	switch (c) {
	case 'A': case 'a': return 10;
	case 'B': case 'b': return 11;
	case 'C': case 'c': return 12;
	case 'D': case 'd': return 13;
	case 'E': case 'e': return 14;
	case 'F': case 'f': return 15;
	}
	return -1;
}

static int
hexpair(const char *s)
{
	int n1, n2;

	if ((n1 = hexval(s[0])) == -1 || (n2 = hexval(s[1])) == -1)
		return -1;
	return n1 << 4 | n2;
}

int
x509cert_parse_dn_string(struct x509cert_rdn *rdn, const char *s, void *bufptr, size_t len)
{
	const char *key;
	unsigned char *buf = bufptr, *bufend = buf + len, *oid, root;
	unsigned long sub;
	int i, j, n, space;

	do {
		rdn->oid = NULL;
		if (isalpha(*s)) {
			key = s;
			while (isalnum(*++s) || *s == '-')
				;
			rdn->oid = keyword(key, s - key);
		} else if (isdigit(*s)) {
			/* parse numeric OID */
			for (i = 0;; ++i, ++s) {
				if (buf == bufend)
					return 0;
				for (sub = 0; '0' <= *s && *s <= '9'; ++s)
					sub = sub * 10 + *s - '0';
				switch (i) {
				case 0:
					if (sub > 3)
						return 0;
					root = sub;
					break;
				case 1:
					rdn->oid = oid = buf;
					if (bufend - buf < 3 || (root < 3 && sub > 39))
						return 0;
					*buf++ = X509CERT_ASN1_OID;
					*buf++ = 1;
					*buf++ = 40 * root + sub;
					break;
				default:
					for (j = 1; sub >> 7 * j; ++j)
						;
					if (bufend - buf < j || 0xff - oid[1] < j)
						return 0;
					oid[1] += j;
					while (--j)
						*buf++ = 0x80 | (sub >> 7 * j & 0x7f);
					*buf++ = sub & 0x7f;
				}
				if (*s != '.')
					break;
			}
		}
		if (!rdn->oid || *s != '=')
			return 0;
		++s;
		rdn->val.val = buf;
		switch (*s) {
		case ' ':
			return 0;
		case '#':
			rdn->val.enc = x509cert_raw_encoder;
			++s;
			while ((n = hexpair(s)) != -1) {
				if (buf == bufend)
					return 0;
				*buf++ = n;
				s += 2;
			}
			break;
		default:
			rdn->val.tag = X509CERT_ASN1_UTF8STRING;
			while (*s && *s != ',') {
				if (buf == bufend)
					return 0;
				if (strchr("\"+;<>", *s))
					return 0;
				space = *s == ' ';
				if (*s == '\\') {
					n = hexpair(++s);
					if (n != -1) {
						*buf++ = n;
						s += 2;
						continue;
					}
					if (!strchr("\\\"+,;<> #=", *s))
						return 0;
				}
				*buf++ = *s++;
			}
			if (space)
				return 0;
		}
		rdn->val.len = buf - (unsigned char *)rdn->val.val;
		++rdn;
		/* multi-valued RDNs are not supported; assume no '+' */
	} while (*s == ',' && *++s);
	if (*s)
		return 0;
	return 1;
}
