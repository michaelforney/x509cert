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
