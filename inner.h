/*
 * Copy an pre-encoded DER item into a buffer, returning the number
 * of bytes copied.
 *
 * The item size must have been encoded as a single byte.
 */
size_t x509cert_copy(const unsigned char *, unsigned char *);

/*
 * Initialize an unsigned ASN.1 INTEGER from its big-endian byte-string
 * representation.
 *
 * This takes care of stripping unnecessary leading zeroes, or
 * adding a leading zero if the highest bit is set (to prevent
 * interpretation as a negative integer).
 */
void x509cert_uint(struct x509cert_item *, const unsigned char *, size_t);

/*
 * DER-encode a SubjectPublicKeyInfo into a buffer (if it is not NULL).
 *
 * The encoded length of the SubjectPublicKeyInfo is returned.
 */
size_t x509cert_encode_pkey(const br_x509_pkey *, unsigned char *);

/*
 * DER-encode an X.509 AlgorithmIdentifier into a buffer (if it is
 * not NULL) for the given signing key type (BR_KEYTYPE_*) and hash
 * ID (br_*_ID).
 *
 * The encoded length of the AlgorithmIdentifier is returned.
 */
size_t x509cert_encode_sign_alg(int key, int hash, unsigned char *);

/*
 * DER-encode a subjectAltName certificate Extension into a buffer
 * (if it is not NULL) from an array of GeneralName items (see RFC
 * 5280).
 *
 * The encoded length of the Extension is returned.
 */
size_t x509cert_encode_san(const struct x509cert_item *, size_t, unsigned char *);
