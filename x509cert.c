#define _DEFAULT_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "x509cert.h"
#include "arg.h"

static const char *argv0;
static unsigned char issuerbuf[4096];
static struct x509cert_dn subject;
static struct x509cert_req req = {.subject = {.enc = x509cert_dn_encoder, .val = &subject}};
static struct x509cert_cert cert = {.req = &req};
static struct x509cert_skey skey;

static void
usage(void)
{
	fprintf(stderr,
		"usage: %s [-C] [-a altname]... [-c issuercert] [-k issuerkey] [-b notbefore] [-d duration] [-s serial] key [subject]\n"
		"       %s -r [-a altname]... key [subject]\n", argv0, argv0);
	exit(1);
}

static void *
xmalloc(size_t n)
{
	void *p;

	p = malloc(n);
	if (!p && n) {
		perror(NULL);
		exit(1);
	}
	return p;
}

static void *
xmallocarray(size_t n, size_t m)
{
	if (m && n > SIZE_MAX / m) {
		errno = ENOMEM;
		perror(NULL);
		exit(1);
	}
	return xmalloc(n * m);
}

static void
add_alt(const char *name)
{
	struct x509cert_item *alt = &req.alts[req.alts_len++];

	alt->tag = X509CERT_SAN_DNSNAME;
	alt->len = strlen(name);
	alt->val = name;
	alt->enc = NULL;
}

/* bearssl's secret key decoder drops the public key part, so
 * we have to recompute it */
static void
compute_pkey(br_x509_pkey *pkey, const struct x509cert_skey *skey)
{
	br_rsa_compute_modulus mod;
	br_rsa_compute_pubexp exp;
	const br_ec_impl *ec;
	uint32_t e;
	unsigned char *buf;
	size_t len;

	switch (skey->type) {
	case BR_KEYTYPE_RSA:
		mod = br_rsa_compute_modulus_get_default();
		exp = br_rsa_compute_pubexp_get_default();
		len = mod(NULL, skey->u.rsa);
		if (len == 0) {
			fputs("failed to compute RSA public key modulus\n", stderr);
			exit(1);
		}
		e = exp(skey->u.rsa);
		if (e == 0) {
			fputs("failed to compute RSA public exponent\n", stderr);
			exit(1);
		}

		len += 4;
		buf = xmalloc(len);
		pkey->key.rsa.e = buf;
		pkey->key.rsa.elen = 4;
		buf[0] = e >> 24;
		buf[1] = e >> 16;
		buf[2] = e >> 8;
		buf[3] = e;
		pkey->key.rsa.n = buf + pkey->key.rsa.elen;
		pkey->key.rsa.nlen = mod(pkey->key.rsa.n, skey->u.rsa);
		break;
	case BR_KEYTYPE_EC:
		ec = br_ec_get_default();
		len = br_ec_compute_pub(ec, NULL, NULL, skey->u.ec);
		if (len == 0) {
			fputs("failed to compute EC public key", stderr);
			exit(1);
		}
		buf = xmalloc(len);
		br_ec_compute_pub(ec, &pkey->key.ec, buf, skey->u.ec);
		break;
	}
	pkey->key_type = skey->type;
}

static br_rsa_private_key *
clone_rsa_skey(const br_rsa_private_key *s)
{
	struct {
		br_rsa_private_key key;
		unsigned char buf[];
	} *d;

	d = xmalloc(sizeof(*d) + s->plen + s->qlen + s->dplen + s->dqlen + s->iqlen);
	d->key = *s;
	d->key.p = d->buf;
	d->key.q = d->key.p + d->key.plen;
	d->key.dp = d->key.q + d->key.qlen;
	d->key.dq = d->key.dp + d->key.dplen;
	d->key.iq = d->key.dq + d->key.dqlen;
	memcpy(d->key.p, s->p, s->plen);
	memcpy(d->key.q, s->q, s->qlen);
	memcpy(d->key.dp, s->dp, s->dplen);
	memcpy(d->key.dq, s->dq, s->dqlen);
	memcpy(d->key.iq, s->iq, s->iqlen);
	return &d->key;
}

static br_ec_private_key *
clone_ec_skey(const br_ec_private_key *s)
{
	struct {
		br_ec_private_key key;
		unsigned char buf[];
	} *d;

	d = xmalloc(sizeof(*d) + s->xlen);
	d->key = *s;
	d->key.x = d->buf;
	memcpy(d->key.x, s->x, s->xlen);
	return &d->key;
}

static void
append_skey(void *ctx, const void *src, size_t len)
{
	br_skey_decoder_push(ctx, src, len);
}

static void
load_key(const char *name, br_x509_pkey *pkey, struct x509cert_skey *skey)
{
	FILE *f;
	br_pem_decoder_context pemctx;
	br_skey_decoder_context keyctx;
	const char *pemname;
	struct x509cert_skey tmpkey;
	unsigned char buf[8192], *pos;
	size_t len = 0, n;
	int err, found = 0;

	f = fopen(name, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", name, strerror(errno));
		exit(1);
	}

	br_pem_decoder_init(&pemctx);
	br_skey_decoder_init(&keyctx);
	tmpkey.type = 0;
	while (!tmpkey.type) {
		if (len == 0) {
			if (feof(f))
				break;
			len = fread(buf, 1, sizeof(buf), f);
			if (ferror(f)) {
				fprintf(stderr, "read %s: %s\n", name, strerror(errno));
				exit(1);
			}
			pos = buf;
		}
		n = br_pem_decoder_push(&pemctx, pos, len);
		pos += n;
		len -= n;
		switch (br_pem_decoder_event(&pemctx)) {
		case BR_PEM_BEGIN_OBJ:
			pemname = br_pem_decoder_name(&pemctx);
			if (strcmp(pemname, BR_ENCODE_PEM_PKCS8) == 0 ||
			    strcmp(pemname, BR_ENCODE_PEM_RSA_RAW) == 0 ||
			    strcmp(pemname, BR_ENCODE_PEM_EC_RAW) == 0)
			{
				br_pem_decoder_setdest(&pemctx, append_skey, &keyctx);
				found = 1;
			}
			break;
		case BR_PEM_END_OBJ:
			if (!found)
				break;
			err = br_skey_decoder_last_error(&keyctx);
			if (err) {
				fprintf(stderr, "parse %s: error %d\n", name, err);
				exit(1);
			}
			tmpkey.type = br_skey_decoder_key_type(&keyctx);
			break;
		case BR_PEM_ERROR:
			fprintf(stderr, "parse %s: PEM decoding error\n", name);
			exit(1);
		}
	}

	switch (tmpkey.type) {
	case BR_KEYTYPE_RSA:
		tmpkey.u.rsa = br_skey_decoder_get_rsa(&keyctx);
		if (skey)
			skey->u.rsa = clone_rsa_skey(tmpkey.u.rsa);
		break;
	case BR_KEYTYPE_EC:
		tmpkey.u.ec = br_skey_decoder_get_ec(&keyctx);
		if (skey)
			skey->u.ec = clone_ec_skey(tmpkey.u.ec);
		break;
	default:
		fprintf(stderr, "parse %s: unsupported key type\n", name);
		exit(1);
	}
	if (skey)
		skey->type = tmpkey.type;
	if (pkey)
		compute_pkey(pkey, &tmpkey);
}

static void
append_dn(void *ctx, const void *buf, size_t len)
{
	struct x509cert_item *item = ctx;

	if (sizeof(issuerbuf) - item->len < len) {
		fprintf(stderr, "issuer DN is too long");
		exit(1);
	}
	memcpy(issuerbuf + item->len, buf, len);
	item->len += len;
}

static void
append_x509(void *ctx, const void *buf, size_t len)
{
	br_x509_decoder_push(ctx, buf, len);
}

static void
load_cert(const char *name, struct x509cert_item *item)
{
	FILE *f;
	br_pem_decoder_context pemctx;
	br_x509_decoder_context x509ctx;
	unsigned char buf[8192], *pos;
	size_t len = 0, n;
	int err, found = 0;

	f = fopen(name, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", name, strerror(errno));
		exit(1);
	}

	br_pem_decoder_init(&pemctx);
	br_x509_decoder_init(&x509ctx, append_dn, item);
	for (;;) {
		if (len == 0) {
			if (feof(f))
				break;
			len = fread(buf, 1, sizeof(buf), f);
			if (ferror(f)) {
				fprintf(stderr, "read %s: %s\n", name, strerror(errno));
				exit(1);
			}
			pos = buf;
		}
		n = br_pem_decoder_push(&pemctx, pos, len);
		pos += n;
		len -= n;
		switch (br_pem_decoder_event(&pemctx)) {
		case BR_PEM_BEGIN_OBJ:
			if (strcmp(br_pem_decoder_name(&pemctx), "CERTIFICATE") == 0) {
				br_pem_decoder_setdest(&pemctx, append_x509, &x509ctx);
				found = 1;
			}
			break;
		case BR_PEM_END_OBJ:
			if (!found)
				break;
			err = br_x509_decoder_last_error(&x509ctx);
			if (err) {
				fprintf(stderr, "parse %s: error %d\n", name, err);
				exit(1);
			}
			if (!br_x509_decoder_isCA(&x509ctx)) {
				fprintf(stderr, "issuer certificate is not a CA\n");
				exit(1);
			}
			break;
		case BR_PEM_ERROR:
			fprintf(stderr, "parse %s: PEM decoding error\n", name);
			exit(1);
		}
	}

	item->tag = 0;
	item->val = issuerbuf;
}

static int
hex(int c)
{
	if ('0' <= c && c <= '9')
		return c - '0';
	switch (c) {
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	}
	fprintf(stderr, "invalid hex character '%c'", c);
	exit(1);
}

static void
parse_serial(const char *s)
{
	if (s) {
		unsigned char *dst;
		const char *end = s + strlen(s);

		if (end == s || (end - s) % 2 != 0) {
			fprintf(stderr, "invalid serial\n");
			exit(1);
		}
		if ((end - s) / 2 > sizeof(cert.serial)) {
			fprintf(stderr, "serial is too large\n");
			exit(1);
		}
		dst = cert.serial + sizeof(cert.serial) - (end - s) / 2;
		for (; s != end; s += 2)
			*dst++ = hex(s[0]) << 4 | hex(s[1]);
	} else if (getentropy(cert.serial + sizeof(cert.serial) - 16, 16) != 0) {
		perror("getentropy");
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	int rflag = 0;
	struct x509cert_item item;
	unsigned long duration = 32ul * 24 * 60 * 60;
	unsigned char *out, *pem;
	size_t outlen, pemlen;
	const char *banner, *certfile = NULL, *keyfile = NULL, *serial = NULL;
	char *end;

	/* at most one subjectAltName per argument */
	if (argc > 3)
		req.alts = xmallocarray(argc - 3, sizeof(req.alts[0]));

	argv0 = argc ? argv[0] : "x509cert";
	ARGBEGIN {
	case 'a':
		add_alt(EARGF(usage()));
		break;
	case 'C':
		cert.ca = 1;
		break;
	case 'c':
		certfile = EARGF(usage());
		break;
	case 'b':
		cert.notbefore = strtoul(EARGF(usage()), &end, 0);
		if (*end)
			usage();
		break;
	case 'd':
		duration = strtoul(EARGF(usage()), &end, 0);
		if (*end)
			usage();
		break;
	case 'k':
		keyfile = EARGF(usage());
		break;
	case 'r':
		rflag = 1;
		break;
	case 's':
		serial = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND
	if (argc < 1 || argc > 2 || (rflag && (certfile || cert.ca)) || !certfile != !keyfile)
		usage();

	if (argc > 1) {
		subject.rdn_len = x509cert_dn_string_rdn_len(argv[1]);
		subject.rdn = xmallocarray(subject.rdn_len, sizeof(subject.rdn[0]));
		if (!x509cert_parse_dn_string(subject.rdn, argv[1])) {
			fputs("invalid subject name\n", stderr);
			return 1;
		}
	}

	if (keyfile) {
		load_key(argv[0], &req.pkey, NULL);
		load_key(keyfile, NULL, &skey);
		load_cert(certfile, &cert.issuer);
	} else {
		load_key(argv[0], &req.pkey, &skey);
		cert.issuer = req.subject;
	}

	if (rflag) {
		banner = "CERTIFICATE REQUEST";
		item.enc = x509cert_req_encoder;
		item.val = &req;
	} else {
		banner = "CERTIFICATE";
		parse_serial(serial);
		if (!cert.notbefore)
			cert.notbefore = time(NULL);
		cert.notafter = cert.notbefore + duration;
		cert.key_type = skey.type;
		cert.hash_id = br_sha256_ID;
		item.enc = x509cert_cert_encoder;
		item.val = &cert;
	}
	outlen = x509cert_sign(&item, &skey, &br_sha256_vtable, NULL);
	if (!outlen) {
		fputs("unsupported key\n", stderr);
		return 1;
	}
	out = xmalloc(outlen);
	outlen = x509cert_sign(&item, &skey, &br_sha256_vtable, out);
	if (!outlen) {
		fputs("signing failed\n", stderr);
		return 1;
	}
	pemlen = br_pem_encode(NULL, out, outlen, banner, BR_PEM_LINE64);
	pem = xmalloc(pemlen + 1);
	br_pem_encode(pem, out, outlen, banner, BR_PEM_LINE64);
	if (fwrite(pem, 1, pemlen, stdout) != pemlen || fflush(stdout) != 0) {
		perror("write");
		return 1;
	}
}
