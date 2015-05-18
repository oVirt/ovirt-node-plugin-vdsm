#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
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
import sys
import ovirtnode.ovirtfunctions as _functions

from ovirt.node import log, utils
from ovirt.node.config.defaults import SSH
from ovirt.node.setup.vdsm import engine_page
from ovirt.node.utils import system

# Log: /var/log/ovirt-node.log
LOGGER = log.getLogger(__name__)
ARGS = system.kernel_cmdline_arguments()


def is_karg_set(key, debug=True):
    """ Check if the key was used as kernel argument """
    if key in ARGS and len(ARGS[key]) > 0:
        if debug:
            LOGGER.info("autoinstall: kernel argument [%s] is set [%s]" %
                        (key, ARGS[key]))
        return ARGS[key]

    return False


def main():
    LOGGER.info("== autoinstall: starting validation for kernel arguments ==")

    # For autoinstall using check-fqdn = False as previous autoinstall
    # doesn't check CA cert
    vdsm_tool_cmd = "vdsm-tool register --check-fqdn False "

    if "ovirt_vdsm_disable" in ARGS:
        LOGGER.info("autoinstall: ovirt_vdsm_disabled is set, nothing to do!")
        return 0

    triggered_autoreg = False
    if is_karg_set("management_server"):
        # Updating OVIRT_MANAGEMENT_SERVER in /etc/default/ovirt
        engine_page.VDSM().update(server=ARGS["management_server"],
                                  port=None,
                                  cert_path=None)
        vdsm_tool_cmd += "--engine-fqdn {s} ".format(
                         s=ARGS["management_server"])
        triggered_autoreg = True

    if is_karg_set("management_server_port"):
        if not is_karg_set("management_server", debug=False):
            LOGGER.error("To use management_server_port is required"
                         " to set management_server key too!")
            return -1
        else:
            # Updating OVIRT_MANAGEMENT and OVIRT_MANAGEMENT_PORT
            # in /etc/default/ovirt
            engine_page.VDSM().update(server=ARGS["management_server"],
                                      port=ARGS["management_server_port"],
                                      cert_path=None)
            vdsm_tool_cmd += "--engine-https-port {p} ".format(
                             p=ARGS["management_server_port"])
            triggered_autoreg = True

    if is_karg_set("management_server_fingerprint"):
        if not is_karg_set("management_server", debug=False):
            LOGGER.error("To use management_server_fingerprint is required"
                         " to set management_server key too!")
            return -1
        else:
            vdsm_tool_cmd += "--fingerprint {f}".format(
                             f=ARGS["management_server_fingerprint"])
            triggered_autoreg = True

    # For rhevm_admin_password/engine_admin_password use:
    # openssl passwd -1 to genereate the password
    admin_pwd = None
    if is_karg_set("rhevm_admin_password"):
        admin_pwd = "rhevm_admin_password"

    if is_karg_set("engine_admin_password"):
        admin_pwd = "engine_admin_password"

    if admin_pwd:
        try:
            _functions.unmount_config("/etc/shadow")
            _functions.unmount_config("/etc/passwd")
            engine_page.execute_cmd("/usr/sbin/usermod -p %s root" %
                                    ARGS[admin_pwd])

            engine_page.execute_cmd("chage -E -1 root")
            utils.fs.Config().persist("/etc/shadow")
            utils.fs.Config().persist("/etc/passwd")
            LOGGER.info("autoinstall: Password updated for user root!")
        except:
            LOGGER.error("autoinstall: Unable to update root password!")
            raise

        # Enable SSHD
        SSH().update(pwauth=True)
        SSH().commit()

    if triggered_autoreg:
        LOGGER.info("autoinstall: vdsm-tool register command")
        LOGGER.info("{c}".format(c=vdsm_tool_cmd))
        out, ret = engine_page.execute_cmd(vdsm_tool_cmd)
        LOGGER.info("autoinstall: vdsm-tool ret: {o}".format(o=out))
        if ret != 0:
            LOGGER.error("autoinstall: vdsm-tool register command FAILED!")
            LOGGER.error("Full log: /var/log/vdsm/register.log")
            return ret

    LOGGER.info("== autoinstall successfully finished ==")

    return 0

if __name__ == "__main__":
    sys.exit(main())
