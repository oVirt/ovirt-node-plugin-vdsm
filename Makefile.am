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

versiondir=$(sysconfdir)/default
nodist_version_DATA = version.$(PACKAGE)

rpms: dist
	rpmbuild $(RPM_FLAGS) -ta $(distdir).tar.gz

srpms: dist
	rpmbuild $(RPM_FLAGS) -ts $(distdir).tar.gz

publish: rpms
	mkdir -p $(OVIRT_CACHE_DIR)
	rsync -aq $(shell rpm --eval '%{_rpmdir}')/ $(OVIRT_CACHE_DIR)/ovirt/
	rsync -aq $(shell rpm --eval '%{_srcrpmdir}')/ $(OVIRT_CACHE_DIR)/ovirt/src
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
