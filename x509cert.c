#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "x509cert.h"
#include "arg.h"

static const char *argv0;
static struct x509cert_dn subject = {.item.enc = x509cert_encode_dn};
static unsigned char issuerbuf[4096];
static struct x509cert_req req = {
	.item.enc = x509cert_encode_req,
	.name = &subject.item,
};
static struct x509cert_cert cert = {
	.item.enc = x509cert_encode_cert,
	.req = &req,
	.issuer = &subject.item,
};
static struct x509cert_skey skey;
static struct asn1_item *alts;

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-r] [-a altname]... [-c issuercert] [-k issuerkey] [-d duration] [-s serial] subject key\n", argv0);
	exit(1);
}

static void *
xmalloc(size_t n)
{
	void *p;

	p = malloc(n);
	if (!p) {
		perror(NULL);
		exit(1);
	}
	return p;
}

static void *
xmallocarray(size_t n, size_t m)
{
	void *p;

	if (m && n > SIZE_MAX / m) {
		errno = ENOMEM;
		p = NULL;
	} else {
		p = malloc(n * m);
	}
	if (!p) {
		perror(NULL);
		exit(1);
	}
	return p;
}

static void
add_alt(const char *name)
{
	struct asn1_item *alt = &alts[req.alts_len++];

	alt->tag = 0x82;
	alt->len = strlen(name);
	alt->val = (const unsigned char *)name;
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
	memcpy(d->key.p, s->p, s->plen);
	d->key.q = d->key.p + d->key.plen;
	memcpy(d->key.q, s->q, s->qlen);
	d->key.dp = d->key.q + d->key.qlen;
	memcpy(d->key.dp, s->dp, s->dplen);
	d->key.dq = d->key.dp + d->key.dplen;
	memcpy(d->key.dq, s->dq, s->dqlen);
	d->key.iq = d->key.dq + d->key.dqlen;
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
	const char *pemname = NULL;
	struct x509cert_skey tmpkey;
	unsigned char buf[8192], *pos;
	size_t len = 0, n;
	int err;

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
			if (strcmp(pemname, BR_ENCODE_PEM_PKCS8) != 0 &&
			    strcmp(pemname, BR_ENCODE_PEM_RSA_RAW) != 0 &&
			    strcmp(pemname, BR_ENCODE_PEM_EC_RAW) != 0)
			{
				pemname = NULL;
				break;
			}
			br_pem_decoder_setdest(&pemctx, append_skey, &keyctx);
			break;
		case BR_PEM_END_OBJ:
			if (!pemname)
				break;
			err = br_skey_decoder_last_error(&keyctx);
			if (err) {
				fprintf(stderr, "parse %s: error %d\n", name, err);
				exit(1);
			}
			tmpkey.type = br_skey_decoder_key_type(&keyctx);
			break;
		case 0:
			break;
		default:
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
	struct asn1_item *item = ctx;

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

static size_t
encode_raw(const struct asn1_item *item, unsigned char *buf)
{
	if (buf)
		memcpy(buf, item->val, item->len);
	return item->len;
}

static const struct asn1_item *
load_cert(const char *name)
{
	static struct asn1_item item = {.enc = encode_raw, .val = issuerbuf};
	FILE *f;
	br_pem_decoder_context pemctx;
	br_x509_decoder_context x509ctx;
	const char *pemname = NULL;
	unsigned char buf[8192], *pos;
	size_t len = 0, n;
	int err;

	f = fopen(name, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", name, strerror(errno));
		exit(1);
	}

	br_pem_decoder_init(&pemctx);
	br_x509_decoder_init(&x509ctx, append_dn, &item);
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
			pemname = br_pem_decoder_name(&pemctx);
			if (strcmp(pemname, "CERTIFICATE") == 0)
				br_pem_decoder_setdest(&pemctx, append_x509, &x509ctx);
			else
				pemname = NULL;
			break;
		case BR_PEM_END_OBJ:
			if (!pemname)
				break;
			err = br_x509_decoder_last_error(&x509ctx);
			if (err) {
				fprintf(stderr, "parse %s: error %d\n", name, err);
				exit(1);
			}
			break;
		case 0:
			break;
		default:
			fprintf(stderr, "parse %s: PEM decoding error\n", name);
			exit(1);
		}
	}

	return &item;
}

int
main(int argc, char *argv[])
{
	int rflag = 0;
	const struct asn1_item *item;
	unsigned long duration = 32ul * 24 * 60 * 60;
	unsigned char *out, *pem;
	size_t outlen, pemlen;
	const char *banner, *certfile = NULL, *keyfile = NULL;
	char *end;

	/* at most one subjectAltName per argument */
	if (argc > 3)
		req.alts = alts = xmallocarray(argc - 3, sizeof(alts[0]));

	argv0 = argc ? argv[0] : "x509cert";
	ARGBEGIN {
	case 'a':
		add_alt(EARGF(usage()));
		break;
	case 'c':
		certfile = EARGF(usage());
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
		break;
	default:
		usage();
	} ARGEND
	if (argc < 2 || argc > 3 || (rflag && certfile) || !certfile != !keyfile)
		usage();

	if (x509cert_parse_dn_string(&subject, argv[0], argv[0], strlen(argv[0])) != 0) {
		fputs("invalid subject name\n", stderr);
		return 1;
	}

	if (keyfile) {
		load_key(argv[1], &req.pkey, NULL);
		load_key(keyfile, NULL, &skey);
		cert.issuer = load_cert(certfile);
	} else {
		load_key(argv[1], &req.pkey, &skey);
	}

	if (rflag) {
		banner = "CERTIFICATE REQUEST";
		item = &req.item;
	} else {
		banner = "CERTIFICATE";
		cert.notbefore = time(NULL);
		cert.notafter = cert.notbefore + duration;
		cert.alg.type = skey.type;
		cert.alg.hash = br_sha256_ID;
		item = &cert.item;
	}
	outlen = x509cert_sign(item, &skey, &br_sha256_vtable, NULL);
	if (!outlen) {
		fputs("unsupported key\n", stderr);
		return 1;
	}
	out = xmalloc(outlen);
	outlen = x509cert_sign(item, &skey, &br_sha256_vtable, out);
	if (!outlen) {
		fputs("signing failed\n", stderr);
		return 1;
	}
	pemlen = br_pem_encode(NULL, out, outlen, banner, BR_PEM_LINE64);
	pem = xmalloc(pemlen);
	br_pem_encode(pem, out, outlen, banner, BR_PEM_LINE64);
	if (fwrite(pem, 1, pemlen, stdout) != pemlen || fflush(stdout) != 0) {
		perror("write");
		return 1;
	}
}
