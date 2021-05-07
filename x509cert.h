#ifndef X509CERT_H
#define X509CERT_H

#include <bearssl.h>
#include <time.h>

struct x509cert_item;

typedef size_t x509cert_encoder(const struct x509cert_item *, unsigned char *);

enum {
	X509CERT_ASN1_INTEGER         = 0x02,
	X509CERT_ASN1_BITSTRING       = 0x03,
	X509CERT_ASN1_OCTETSTRING     = 0x04,
	X509CERT_ASN1_NULL            = 0x05,
	X509CERT_ASN1_OID             = 0x06,
	X509CERT_ASN1_UTF8STRING      = 0x0c,
	X509CERT_ASN1_IA5STRING       = 0x16,
	X509CERT_ASN1_GENERALIZEDTIME = 0x18,
	X509CERT_ASN1_SEQUENCE        = 0x30,
	X509CERT_ASN1_SET             = 0x31,
};

/* ASN.1 item */
struct x509cert_item {
	int tag;
	size_t len;
	const void *val;
	x509cert_encoder *enc;
};

/*
 * DER-encode an ASN.1 item into a buffer.
 *
 * If the buffer is NULL, the encoded length of the item is returned.
 *
 * Otherwise, if enc is NULL, the item tag, length, and value (if
 * it is not NULL) are encoded into the buffer and the number of
 * bytes encoded is returned.
 *
 * If enc is not NULL, a custom encoder function is used to encode
 * the value.
 */
size_t x509cert_encode(const struct x509cert_item *, unsigned char *);

/*
 * Initialize an unsigned ASN.1 INTEGER from its big-endian byte-string
 * representation.
 *
 * This takes care of stripping unnecessary leading zeroes, or
 * adding a leading zero if the highest bit is set (to prevent
 * interpretation as a negative integer).
 */
void x509cert_uint(struct x509cert_item *, const unsigned char *, size_t);

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
	struct x509cert_item val;
};

/* X.501 DistinguishedName */
struct x509cert_dn {
	struct x509cert_rdn *rdn;
	size_t rdn_len;
};

/* subjectAltName GeneralName tags (RFC 5280 4.2.1.6) */
enum {
	X509CERT_SAN_OTHERNAME  = 0xa0,  /* SEQUENCE { OID, ANY } */
	X509CERT_SAN_RFC822NAME = 0x81,  /* IA5String */
	X509CERT_SAN_DNSNAME    = 0x82,  /* IA5String */
	X509CERT_SAN_URI        = 0x86,  /* IA5String */
	X509CERT_SAN_IPADDRESS  = 0x87,  /* OCTET STRING */
};

/* PKCS#10 CertificateRequestInfo */
struct x509cert_req {
	struct x509cert_item subject;
	br_x509_pkey pkey;
	const struct x509cert_item *alts;
	size_t alts_len;
};

/* X.509 TBSCertificate */
struct x509cert_cert {
	const struct x509cert_req *req;
	struct x509cert_item serial;
	int key_type;  /* BR_KEYTYPE_* */
	int hash_id;  /* br_*_ID */
	struct x509cert_item issuer;
	time_t notbefore, notafter;
	int ca;
};

extern x509cert_encoder x509cert_dn_encoder;
extern x509cert_encoder x509cert_req_encoder;
extern x509cert_encoder x509cert_cert_encoder;

extern const unsigned char x509cert_oid_CN[];
extern const unsigned char x509cert_oid_L[];
extern const unsigned char x509cert_oid_ST[];
extern const unsigned char x509cert_oid_O[];
extern const unsigned char x509cert_oid_OU[];
extern const unsigned char x509cert_oid_C[];
extern const unsigned char x509cert_oid_STREET[];

/*
 * DER-encode a DistinguishedName into a buffer (if it is not NULL).
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
 * DER-encode a PKCS#10 CertificateRequestInfo into a buffer (if
 * it is not NULL).
 *
 * The encoded length of the CertificateRequestInfo is returned.
 */
size_t x509cert_encode_req(const struct x509cert_req *, unsigned char *);

/*
 * DER-encode an X.509 TBSCertificate into a buffer (if it is not
 * NULL).
 *
 * The encoded length of the TBSCertificate is returned.
 */
size_t x509cert_encode_cert(const struct x509cert_cert *, unsigned char *);

/*
 * Sign an ASN.1 item, and DER-encode the item and its signature
 * as an X.509 SIGNED{...} item into a buffer (if it is not NULL).
 *
 * If the buffer is NULL, the signature is not computed and the
 * *maximum* length of the SIGNED item is returned. The actual
 * length may be slightly smaller, depending on the signature.
 *
 * If the key is not supported or there is an error computing the
 * signature, 0 is returned.
 */
size_t x509cert_sign(const struct x509cert_item *, const struct x509cert_skey *, const br_hash_class *, unsigned char *);

#endif
