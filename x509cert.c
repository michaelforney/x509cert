#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "x509cert.h"
#include "arg.h"

static const char *argv0;
static struct x509cert_dn subject = {.item.enc = x509cert_encode_dn};
static struct x509cert_req req = {.item.enc = x509cert_encode_req};
static struct x509cert_skey skey;
static struct asn1_item *alts;
static size_t alts_len;

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
	struct asn1_item *alt = &alts[alts_len++];

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

static void
append_skey(void *ctx, const void *src, size_t len)
{
	br_skey_decoder_push(ctx, src, len);
}

static void
load_key(const char *name, br_x509_pkey *pkey, struct x509cert_skey *skey)
{
	static br_skey_decoder_context keyctx;
	FILE *f;
	br_pem_decoder_context pemctx;
	const char *pemname = NULL;
	unsigned char buf[8192], *pos;
	size_t len = 0, n;
	int type = 0, err;

	f = fopen(name, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", name, strerror(errno));
		exit(1);
	}

	br_pem_decoder_init(&pemctx);
	br_skey_decoder_init(&keyctx);
	while (!type) {
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
			type = br_skey_decoder_key_type(&keyctx);
			break;
		case 0:
			break;
		default:
			fprintf(stderr, "parse %s: PEM decoding error\n", name);
			exit(1);
		}
	}

	switch (type) {
	case BR_KEYTYPE_RSA:
		skey->u.rsa = br_skey_decoder_get_rsa(&keyctx);
		break;
	case BR_KEYTYPE_EC:
		skey->u.ec = br_skey_decoder_get_ec(&keyctx);
		break;
	default:
		fprintf(stderr, "parse %s: unsupported key type\n", name);
		exit(1);
	}
	skey->type = type;
	if (pkey)
		compute_pkey(pkey, skey);
}

int
main(int argc, char *argv[])
{
	int rflag = 0;
	const struct asn1_item *item;
	unsigned long duration = 32ul * 24 * 60 * 60;
	unsigned char *out, *pem;
	size_t outlen, pemlen;
	const char *banner;
	char *end;

	/* at most one subjectAltName per argument */
	if (argc > 3)
		alts = xmallocarray(argc - 3, sizeof(alts[0]));

	argv0 = argc ? argv[0] : "x509cert";
	ARGBEGIN {
	case 'a':
		add_alt(EARGF(usage()));
		break;
	case 'c':
		break;
	case 'd':
		duration = strtoul(EARGF(usage()), &end, 0);
		if (*end)
			usage();
		break;
	case 'k':
		break;
	case 'r':
		rflag = 1;
		break;
	case 's':
		break;
	default:
		usage();
	} ARGEND
	if (argc < 2 || argc > 3)
		usage();

	if (x509cert_parse_dn_string(&subject, argv[0], argv[0], strlen(argv[0])) != 0) {
		fputs("invalid subject name\n", stderr);
		return 1;
	}

	load_key(argv[1], &req.pkey, &skey);

	if (rflag) {
		banner = "CERTIFICATE REQUEST";
		req.name = &subject.item;
		req.alts = alts;
		req.alts_len = alts_len;
		item = &req.item;
	} else {
		banner = "CERTIFICATE";
		fputs("generating certificate not yet supported\n", stderr);
		return 1;
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
