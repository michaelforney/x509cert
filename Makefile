.POSIX:
.PHONY: all install clean

PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
LIBDIR=$(PREFIX)/lib
INCDIR=$(PREFIX)/include
MANDIR=$(PREFIX)/share/man

CFLAGS+=-Wall -Wpedantic
LDLIBS=-l bearssl

-include config.mk

OBJ=\
	cert.o\
	der.o\
	dn.o\
	dn_string.o\
	oid.o\
	pkey.o\
	req.o\
	san.o\
	sign.o

all: libx509cert.a x509cert

$(OBJ) x509cert.o: x509cert.h inner.h

libx509cert.a: $(OBJ)
	$(AR) $(ARFLAGS) $@ $(OBJ)

x509cert: x509cert.o libx509cert.a
	$(CC) $(LDFLAGS) -o $@ x509cert.o libx509cert.a $(LDLIBS)

install: x509cert libx509cert.a
	mkdir -p $(DESTDIR)$(BINDIR)
	cp x509cert $(DESTDIR)$(BINDIR)/
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	cp x509cert.1 $(DESTDIR)$(MANDIR)/man1/
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	cp x509cert.3 $(DESTDIR)$(MANDIR)/man3/
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp libx509cert.a $(DESTDIR)$(LIBDIR)/
	mkdir -p $(DESTDIR)$(INCDIR)
	cp x509cert.h $(DESTDIR)$(INCDIR)/

clean:
	rm -f $(OBJ) libx509cert.a x509cert.o x509cert
