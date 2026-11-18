MAKEFILE_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

APP_VERSION := $(shell git describe --tags --always --dirty)
ifndef APP_VERSION
$(error APP_VERSION not set (git issue?))
endif

APP_VERSION_NUM := $(shell echo "$(APP_VERSION)" | sed 's/^v//')

CFLAGS := -O2 -Wall -Wextra -Wpedantic \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong \
	-Wformat -Werror=format-security \
	-fPIE -pie -Wl,-z,relro,-z,now \
	-DAPP_VERSION_NUM=\"$(APP_VERSION_NUM)\"

DEB_ROOT := $(MAKEFILE_DIR)/bin/deb/nfwpunch_$(APP_VERSION_NUM)-1

.PHONY: \
	$(MAKEFILE_DIR)/bin/nfwpunchd \
	nfwpunchd \
	all \
	deb \
	clean \
	doc \
	install

all: \
	deb

$(MAKEFILE_DIR)/bin/nfwpunchd:
	@ mkdir -p $(MAKEFILE_DIR)/bin
	cd $(MAKEFILE_DIR)/bin && gcc $(CFLAGS) -o nfwpunchd $(MAKEFILE_DIR)/nfwpunchd.c

nfwpunchd: $(MAKEFILE_DIR)/bin/nfwpunchd

doc: $(MAKEFILE_DIR)/bin/nfwpunch.8.gz

$(MAKEFILE_DIR)/bin/nfwpunch.8.gz: $(MAKEFILE_DIR)/doc/nfwpunch.8.scd
	scdoc < $< | gzip > $@

clean:
	@ rm $(MAKEFILE_DIR)/bin/nfwpunchd > /dev/null 2>&1 || true
	@ rm -f $(MAKEFILE_DIR)/bin/nfwpunch.8.gz > /dev/null 2>&1 || true
	@ rm -rf $(MAKEFILE_DIR)/bin/deb > /dev/null 2>&1 || true
	@ rm -f $(MAKEFILE_DIR)/bin/nfwpunch_*.deb > /dev/null 2>&1 || true

install: nfwpunchd
	install -m 0755 -D $(MAKEFILE_DIR)/bin/nfwpunchd /usr/sbin/nfwpunchd
	install -m 0644 -D -t /etc $(MAKEFILE_DIR)/dist/etc/nfwpunch.conf
	install -m 0644 -D -t /lib/systemd/system $(MAKEFILE_DIR)/dist/lib/systemd/system/nfwpunch.service
	[ -e $(MAKEFILE_DIR)/bin/nfwpunch.8.gz ] && \
		install -m 0644 -D -t /usr/share/man/man8 $(MAKEFILE_DIR)/bin/nfwpunch.8.gz
	install -m 0644 -D $(MAKEFILE_DIR)/LICENSE /usr/share/doc/nfwpunch/copyright
	install -m 0644 -D $(MAKEFILE_DIR)/examples/nginx-lua/nfwpunchd-nginx.conf /usr/share/doc/nfwpunch/examples/nginx-lua/nfwpunchd-nginx.conf
	install -m 0644 -D $(MAKEFILE_DIR)/examples/nginx-perl/nfwpunchd-nginx.conf /usr/share/doc/nfwpunch/examples/nginx-perl/nfwpunchd-nginx.conf
	install -m 0644 -D $(MAKEFILE_DIR)/examples/nginx-perl/nfwpunchd-nginx.pl /usr/share/doc/nfwpunch/examples/nginx-perl/nfwpunchd-nginx.pl

deb: nfwpunchd doc
	$(eval $@_ARCH = $(shell gcc -dumpmachine | cut -d'-' -f1 | sed 's/x86_64/amd64/'))

	rm -rf $(MAKEFILE_DIR)/bin/deb

	install -m 0644 -D $(MAKEFILE_DIR)/debian/control.in $(DEB_ROOT)/DEBIAN/control
	sed -i "s/@VERSION@/$(APP_VERSION_NUM)/g" $(DEB_ROOT)/DEBIAN/control
	sed -i "s/@ARCH@/${$@_ARCH}/g" $(DEB_ROOT)/DEBIAN/control
	install -m 0644 -D $(MAKEFILE_DIR)/debian/conffiles $(DEB_ROOT)/DEBIAN/conffiles
	install -m 0755 -D $(MAKEFILE_DIR)/debian/postinst $(DEB_ROOT)/DEBIAN/postinst
	install -m 0755 -D $(MAKEFILE_DIR)/debian/postrm $(DEB_ROOT)/DEBIAN/postrm

	install -m 0755 -D $(MAKEFILE_DIR)/bin/nfwpunchd $(DEB_ROOT)/usr/sbin/nfwpunchd
	install -m 0644 -D -t $(DEB_ROOT)/etc $(MAKEFILE_DIR)/dist/etc/nfwpunch.conf
	install -m 0644 -D -t $(DEB_ROOT)/lib/systemd/system $(MAKEFILE_DIR)/dist/lib/systemd/system/nfwpunch.service
	install -m 0644 -D -t $(DEB_ROOT)/usr/share/man/man8 $(MAKEFILE_DIR)/bin/nfwpunch.8.gz
	install -m 0644 -D $(MAKEFILE_DIR)/LICENSE $(DEB_ROOT)/usr/share/doc/nfwpunch/copyright
	install -m 0644 -D $(MAKEFILE_DIR)/examples/nginx-lua/nfwpunchd-nginx.conf $(DEB_ROOT)/usr/share/doc/nfwpunch/examples/nginx-lua/nfwpunchd-nginx.conf
	install -m 0644 -D $(MAKEFILE_DIR)/examples/nginx-perl/nfwpunchd-nginx.conf $(DEB_ROOT)/usr/share/doc/nfwpunch/examples/nginx-perl/nfwpunchd-nginx.conf
	install -m 0644 -D $(MAKEFILE_DIR)/examples/nginx-perl/nfwpunchd-nginx.pl $(DEB_ROOT)/usr/share/doc/nfwpunch/examples/nginx-perl/nfwpunchd-nginx.pl

	cd $(MAKEFILE_DIR)/bin/deb && dpkg-deb --build nfwpunch_$(APP_VERSION_NUM)-1 && \
		mv nfwpunch_$(APP_VERSION_NUM)-1.deb ../nfwpunch_$(APP_VERSION_NUM)-1-${$@_ARCH}.deb
