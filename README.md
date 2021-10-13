# x509cert

[![builds.sr.ht status](https://builds.sr.ht/~mcf/x509cert.svg)](https://builds.sr.ht/~mcf/x509cert)

x509cert is a tool and library for generating X.509 certificates
and certificate requests. It is written in C99 and uses [BearSSL]
to decode keys and compute signatures.

Like BearSSL, libx509cert makes minimal use of the standard library.
It does not do any dynamic allocation, and uses only a few basic
libc functions.

## Tool usage

	x509cert [-C] [-a altname]... [-c issuercert] [-k issuerkey] [-b notbefore] [-d duration] [-s serial] key [subject]
	x509cert -r [-a altname]... key [subject]

If `-r` is used, a PKCS#10 CertificateRequest is created. Otherwise,
an X.509 Certificate is created. In either case, the structure is
PEM-encoded and written to standard output. For more details, see
[x509cert(1)].

## Library usage

See [x509cert(3)].

[BearSSL]: https://bearssl.org
[x509cert(1)]: https://x509cert.mforney.org/x509cert.1.html
[x509cert(3)]: https://x509cert.mforney.org/x509cert.3.html
