# Copyright (C) 2008 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.  A copy of the GNU General Public License is
# also available at http://www.gnu.org/copyleft/gpl.html.

OVIRT_CACHE_DIR	?= $(HOME)/ovirt-cache

PYTHONSOURCES = \
  $(shell find src -name \*.py)

SHELL := /bin/bash


SUBDIRS = \
	conf \
	autoinstall \
	vdsm-upgrade \
	hooks \
	src \
	systemd \
	recipe

EXTRA_DIST = \
  ovirt-node-plugin-vdsm.spec \
  ovirt-node-plugin-vdsm.spec.in

DISTCLEANFILES = $(PACKAGE)-$(VERSION).tar.gz \
	aclocal.m4 \
	configure \
	install-sh \
	missing \
	py-compile

DISTCLEANDIRS = autom4te.cache

TMPREPOS = tmp.repos
RPM_FLAGS := --define="_topdir `pwd`/$(TMPREPOS)"

versiondir=$(sysconfdir)/default
nodist_version_DATA = version.$(PACKAGE)

srpms: dist
	rm -rf "$(TMPREPOS)"
	mkdir -vp $(TMPREPOS)/{SPECS,RPMS,SRPMS,SOURCES}
	rpmbuild $(RPM_FLAGS) -ta $(distdir).tar.gz
	@echo
	@echo "srpm available at '$(TMPREPOS)'"
	@echo

rpms: srpms
	rpmbuild $(RPM_FLAGS) --rebuild "$(TMPREPOS)"/SRPMS/*.src.rpm
	@echo
	@echo "rpm available at '$(TMPREPOS)'"
	@echo

publish: rpms
	$(MAKE)
	$(MAKE) create-repo

create-repo:
	mkdir -p $(OVIRT_CACHE_DIR)
	rsync -qa $(TMPREPOS) /$(OVIRT_CACHE_DIR)/ovirt
	createrepo $(OVIRT_CACHE_DIR)/ovirt

iso: publish
	cd recipe
	make node

.PHONY: rpms publish srpms

check-local: static-checks
	  @echo Passed $@

static-checks:
	  $(MAKE) -C src/ check-local

# vim: ts=2
