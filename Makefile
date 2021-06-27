.POSIX:
.PHONY: all install clean

VERSION=0.4
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

x509cert.pc: x509cert.pc.in
	sed -e 's,@version@,$(VERSION),'\
	    -e 's,@libdir@,$(LIBDIR),'\
	    -e 's,@includedir@,$(INCDIR),'\
	    x509cert.pc.in >$@.tmp && mv $@.tmp $@

install: x509cert libx509cert.a x509cert.pc
	mkdir -p $(DESTDIR)$(BINDIR)
	cp x509cert $(DESTDIR)$(BINDIR)/
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	cp x509cert.1 $(DESTDIR)$(MANDIR)/man1/
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	cp x509cert.3 $(DESTDIR)$(MANDIR)/man3/
	mkdir -p $(DESTDIR)$(LIBDIR)/pkgconfig
	cp libx509cert.a $(DESTDIR)$(LIBDIR)/
	cp x509cert.pc $(DESTDIR)$(LIBDIR)/pkgconfig/
	mkdir -p $(DESTDIR)$(INCDIR)
	cp x509cert.h $(DESTDIR)$(INCDIR)/

clean:
	rm -f $(OBJ) libx509cert.a x509cert.o x509cert x509cert.pc
