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
	struct x509cert_rdn *rdn;
	size_t rdn_len;
};

/* PKCS#10 CertificateRequestInfo */
struct x509cert_req {
	struct asn1_item subject;
	const struct asn1_item *alts;
	size_t alts_len;
	br_x509_pkey pkey;
};

struct x509cert_cert {
	const struct x509cert_req *req;
	struct asn1_uint serial;
	struct {
		int type;
		int hash;
	} alg;
	struct asn1_item issuer;
	time_t notbefore, notafter;
};

extern asn1_encoder x509cert_dn_encoder;
extern asn1_encoder x509cert_req_encoder;
extern asn1_encoder x509cert_cert_encoder;

extern const unsigned char x509cert_oid_CN[];
extern const unsigned char x509cert_oid_L[];
extern const unsigned char x509cert_oid_ST[];
extern const unsigned char x509cert_oid_O[];
extern const unsigned char x509cert_oid_OU[];
extern const unsigned char x509cert_oid_C[];
extern const unsigned char x509cert_oid_STREET[];

/*
 * Encode a DistinguishedName into a buffer (if it is not NULL).
 *
 * The item must point to the item member of a struct x509cert_dn.
 *
 * The encoded length of the DN is returned.
 */
size_t x509cert_encode_dn(const struct x509cert_dn *, unsigned char *);

/*
 * Determine the number of RDN components in an RFC 1779 string
 * representation of a DistinguishedName.
 */
size_t x509cert_dn_string_rdn_len(const char *);

/*
 * Parse an RFC 1779 string representation of a DistinguishedName.
 *
 * The given buffer is used to store the RDN values. The number of
 * bytes used is less than length of the string. It may point to
 * the same buffer as the string.
 *
 * The RDN array is populated and must be large enough to accomodate
 * all RDN components.
 *
 * Returns 1 on success, or 0 on parse error.
 */
int x509cert_parse_dn_string(struct x509cert_rdn *, const char *, void *, size_t);

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
size_t x509cert_encode_req(const struct x509cert_req *, unsigned char *);

/*
 * Encode an X.509 TBSCertificate into a buffer (if it is not NULL).
 *
 * This is the to-be-signed data in a Certificate.
 *
 * The encoded length of the TBSCertificate is returned.
 */
size_t x509cert_encode_cert(const struct x509cert_cert *, unsigned char *);

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
