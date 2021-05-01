#include <string.h>
#include "asn1.h"

static size_t
encode_len(size_t len, unsigned char *buf)
{
	size_t x;
	int n, i;

	if (len < 0x80) {
		if (buf)
			buf[0] = len;
		return 1;
	}
	for (x = len, n = 0; x; x >>= 8, ++n)
		;
	if (buf) {
		*buf++ = 0x80 | n;
		for (i = n - 1; i >= 0; --i)
			*buf++ = len >> (i << 3);
	}
	return 1 + n;
}

size_t
asn1_copy(const unsigned char *oid, unsigned char *buf)
{
	size_t len = 2 + oid[1];

	if (buf)
		memcpy(buf, oid, len);
	return len;
}

size_t
asn1_encode(const struct asn1_item *item, unsigned char *buf)
{
	unsigned char *pos;

	if (item->enc)
		return item->enc(item, buf);
	if (!buf)
		return 1 + encode_len(item->len, NULL) + item->len;
	pos = buf;
	*pos++ = item->tag;
	pos += encode_len(item->len, pos);
	if (item->val) {
		memcpy(pos, item->val, item->len);
		pos += item->len;
	}
	return pos - buf;
}

void
asn1_uint(struct asn1_uint *uint, const unsigned char *buf, size_t len)
{
	while (len > 0 && buf[0] == 0)
		--len, ++buf;
	uint->buf = buf;
	uint->len = len;
}

size_t
asn1_encode_uint(const struct asn1_uint *uint, unsigned char *buf)
{
	struct asn1_item item = {ASN1_INTEGER};
	int pad;
	unsigned char *pos;
	size_t len;

	pad = uint->len == 0 || uint->buf[0] & 0x80;
	item.len = uint->len + pad;
	len = asn1_encode(&item, buf);
	if (!buf)
		return len;
	pos = buf + len;
	if (pad)
		*pos++ = 0;
	memcpy(pos, uint->buf, uint->len);
	pos += uint->len;
	return pos - buf;
}
