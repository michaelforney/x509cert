#ifndef X509CERT_H
#define X509CERT_H

#include <asn1.h>
#include <bearssl.h>

struct x509cert_skey {
	int type;
	union {
		const br_rsa_private_key *rsa;
		const br_ec_private_key *ec;
	} u;
};

/* X.501 RelativeDistinguishedName */
struct x509cert_rdn {
	const unsigned char *oid;
	struct asn1_item val;
};

/* X.501 DistinguishedName */
struct x509cert_dn {
	struct x509cert_rdn *rdn;
	size_t rdn_len;
};

/* PKCS#10 CertificateRequestInfo */
struct x509cert_req_info {
	struct x509cert_dn name;
	const struct asn1_item *alts;
	size_t alts_len;
	br_x509_pkey pkey;
};

/*
 * Encode a RelativeDistinguishedName into a buffer (if it is not
 * NULL).
 *
 * The encoded length of the RDN is returned.
 */
size_t x509cert_encode_rdn(const struct x509cert_rdn *, unsigned char *);

int x509cert_parse_dn_string(struct x509cert_dn *, const char *, unsigned char *, size_t);

/*
 * Encode a DistinguishedName into a buffer (if it is not NULL).
 *
 * The encoded length of the DN is returned.
 */
size_t x509cert_encode_dn(const struct x509cert_dn *, unsigned char *);

/*
 * Encode a SubjectPublicKeyInfo into a buffer (if it is not NULL).
 *
 * The encoded length of the SubjectPublicKeyInfo is returned.
 */
size_t x509cert_encode_pkey(const br_x509_pkey *, unsigned char *);

/*
 * Encode an X.509 AlgorithmIdentifier into a buffer (if it is not
 * NULL) for the given signing key type (BR_KEYTYPE_*) and hash ID
 * (br_*_ID).
 *
 * The encoded length of the AlgorithmIdentifier is returned.
 */
size_t x509cert_encode_sign_alg(int key, int hash, unsigned char *);

/*
 * Encode a PKCS#10 CertificateRequestInfo into a buffer (if it is
 * not NULL).
 *
 * The encoded length of the CertificateRequestInfo is returned.
 */
size_t x509cert_encode_req_info(const struct x509cert_req_info *, unsigned char *);

/*
 * Sign an ASN.1 item, and encode the item and its signature as an
 * X.509 SIGNED{...} item into a buffer (if it is not NULL).
 *
 * If the buffer is NULL, the signature is not computed and the
 * *maximum* length of the SIGNED item is returned. The actual
 * length may be smaller, depending on the signature.
 *
 * If the key is not supported or there is an error computing the
 * signature, 0 is returned.
 */
size_t x509cert_sign(const struct asn1_item *, const struct x509cert_skey *, const br_hash_class *, unsigned char *);

size_t x509cert_req(const struct x509cert_req_info *, const struct x509cert_skey *, const br_hash_class *, unsigned char *);

#endif
