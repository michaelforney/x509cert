#ifndef X509CERT_H
#define X509CERT_H

#include <asn1.h>
#include <bearssl.h>
#include <time.h>

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
	struct asn1_item item;
	struct x509cert_rdn *rdn;
	size_t rdn_len;
};

/* PKCS#10 CertificateRequestInfo */
struct x509cert_req {
	struct asn1_item item;
	const struct asn1_item *name;
	const struct asn1_item *alts;
	size_t alts_len;
	br_x509_pkey pkey;
};

struct x509cert_cert {
	struct asn1_item item;
	const struct x509cert_req *req;
	struct asn1_uint serial;
	struct {
		int type;
		int hash;
	} alg;
	const struct asn1_item *issuer;
	time_t notbefore, notafter;
};

/*
 * Encode a DistinguishedName into a buffer (if it is not NULL).
 *
 * The item must point to the item member of a struct x509cert_dn.
 *
 * The encoded length of the DN is returned.
 */
size_t x509cert_encode_dn(const struct asn1_item *, unsigned char *);

/*
 * Parse an RFC 1779 string representation of a DistinguishedName.
 *
 * The given buffer is used to store the RDN values. The number of
 * bytes used is at most the length of the string. It may point to
 * the same buffer as the string.
 *
 * The RDN array is allocated and placed in the DN.
 *
 * Returns 0 on success. Returns -1 if allocation fails or there
 * was a parse error.
 */
int x509cert_parse_dn_string(struct x509cert_dn *, const char *, void *, size_t);

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
 * Encode a subjectAltName certificate Extension into a buffer (if
 * it is not NULL) from an array of GeneralName items (see RFC
 * 5280).
 *
 * The encoded length of the Extension is returned.
 */
size_t x509cert_encode_san(const struct asn1_item *, size_t, unsigned char *);

/*
 * Encode a PKCS#10 CertificateRequestInfo into a buffer (if it is
 * not NULL).
 *
 * The encoded length of the CertificateRequestInfo is returned.
 */
size_t x509cert_encode_req(const struct asn1_item *, unsigned char *);

/*
 * Encode an X.509 TBSCertificate into a buffer (if it is not NULL).
 *
 * This is the to-be-signed data in a Certificate.
 *
 * The encoded length of the TBSCertificate is returned.
 */
size_t x509cert_encode_cert(const struct asn1_item *, unsigned char *);

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

#endif
