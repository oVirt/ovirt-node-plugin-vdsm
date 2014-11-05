# Copyright (C) 2014 Red Hat, Inc.
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

preupgradedir = $(libexecdir)/ovirt-node/hooks/pre-upgrade
postupgradedir = $(libexecdir)/ovirt-node/hooks/post-upgrade
onbootdir = $(libexecdir)/ovirt-node/hooks/on-boot

dist_preupgrade_SCRIPTS = \
	pre-upgrade/01-vdsm \
	$(NULL)

dist_postupgrade_SCRIPTS = \
	post-upgrade/01-sanlock-check \
	$(NULL)

dist_onboot_SCRIPTS = \
	on-boot/01-vdsm-configure \
	on-boot/02-vdsm-sebool-config \
	$(NULL)
