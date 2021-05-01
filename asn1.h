#ifndef ASN1_H
#define ASN1_H

#include <stddef.h>

enum {
	ASN1_INTEGER 	 = 0x02,
	ASN1_BITSTRING 	 = 0x03,
	ASN1_OCTETSTRING = 0x04,
	ASN1_NULL 	 = 0x05,
	ASN1_OID 	 = 0x06,
	ASN1_UTF8STRING  = 0x0c,
	ASN1_IA5STRING   = 0x16,
	ASN1_SEQUENCE 	 = 0x30,
	ASN1_SET 	 = 0x31,
};

struct asn1_item {
	int tag;
	size_t len;
	const unsigned char *val;
	size_t (*enc)(const struct asn1_item *, unsigned char *);
};

struct asn1_uint {
	const unsigned char *buf;
	size_t len;
};

/*
 * Encode an ASN.1 item into a buffer.
 *
 * If the buffer is NULL, the encoded length of the item is returned.
 *
 * Otherwise, the item tag, length, and value (if it is not NULL)
 * are encoded into the buffer and the number of bytes encoded is
 * returned.
 */
size_t asn1_encode(const struct asn1_item *, unsigned char *);

/*
 * Copy an pre-encoded DER item into a buffer, returning the number
 * of bytes copied.
 *
 * The item size must have been encoded as a single byte.
 */
size_t asn1_copy(const unsigned char *, unsigned char *);

/*
 * Initialize an unsigned ASN.1 INTEGER from its big-endian byte-string
 * representation.
 */
void asn1_uint(struct asn1_uint *, const unsigned char *, size_t);

/*
 * Encode an unsigned ASN.1 INTEGER into a buffer.
 *
 * This routine is separate from asn1_encode since it has to account
 * for a zero-length integer, or one with the most-significant bit
 * set.
 */
size_t asn1_encode_uint(const struct asn1_uint *, unsigned char *);

#endif
