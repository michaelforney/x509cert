.POSIX:
.PHONY: all clean

-include config.mk

CFLAGS+=-Wall -Wpedantic -I .
LDLIBS=-l bearssl

OBJ=\
	asn1.o\
	dn.o\
	pkey.o\
	req.o\
	san.o\
	sign.o

all: libx509cert.a x509cert

$(OBJ) x509cert.o: asn1.h x509cert.h

libx509cert.a: $(OBJ)
	$(AR) $(ARFLAGS) $@ $(OBJ)

x509cert: x509cert.o libx509cert.a
	$(CC) $(LDFLAGS) -o $@ x509cert.o libx509cert.a $(LDLIBS)

clean:
	rm -f $(OBJ) libx509cert.a x509cert.o x509cert
