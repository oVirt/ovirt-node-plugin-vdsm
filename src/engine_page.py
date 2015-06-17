#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# engine_page.py - Copyright (C) 2012-2015 Red Hat, Inc.
# Written by Fabian Deutsch <fabiand@redhat.com>
#            Douglas Schilling Landgraf <dougsland@redhat.com>
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
import augeas
import errno
import subprocess
import shlex

from . import config
from socket import error as socket_error

from ovirt.node import plugins, valid, ui, utils, log
from ovirt.node.config.defaults import NodeConfigFileSection, SSH
from ovirt.node.plugins import Changeset

from vdsm import vdscli

"""
Configure Engine
"""


LOGGER = log.getLogger(__name__)


def execute_cmd(cmd, env_shell=False):
    try:
        cmd = subprocess.Popen(shlex.split(cmd),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               shell=env_shell)

        output, err = cmd.communicate()

    except OSError:
        LOGGER.debug("Cannot execute cmd {c}, err {e}".format(c=cmd, e=err))

    return output, cmd.returncode


def validate_server(server):
    """Validate server str if user provided ':' port schema"""
    return True if ":" in server else False


def _hack_to_workaround_pyaug_issues(mgmtIface, cfg, engine_data):
    """Normally we must not use the Augeas() class directly.
    Instead we interact with the /etc/default/ovirt class through
    the ovirt.node.config.defaults module and it's classes.
    However, this hack is needed to workaround the problem that
    the augeas object is cachign some values, and will flush them to disk
    occasionally.
    This can only be fixed by removing all calls to augeas
    or by a different solution.
    """
    ag = augeas.Augeas()
    ag.set("/augeas/save/copy_if_rename_fails", "")
    ag.set("/files/etc/default/ovirt/MANAGED_IFNAMES", "\"%s\"" %
           ''.join(mgmtIface).encode('utf-8'))
    ag.set("/files/etc/default/ovirt/OVIRT_MANAGEMENT_SERVER", "\"%s\"" %
           cfg["server"])
    ag.set("/files/etc/default/ovirt/OVIRT_MANAGEMENT_PORT", "\"%s\"" %
           cfg["port"])

    if engine_data is not None and engine_data != "":
        ag.set("/files/etc/default/ovirt/MANAGED_BY",
               engine_data.encode('utf-8'))
    ag.save()


def sync_mgmt():
    """Guess mgmt interface and update TUI config
       FIXME: Autoinstall should write MANAGED_BY and MANAGED_IFNAMES
       into /etc/defaults/ovirt
    """
    engine_data = None
    cfg = VDSM().retrieve()

    mgmtIface = []

    try:
        cli = vdscli.connect()
        networks = cli.getVdsCapabilities()['info']['networks']

        for net in networks:
            if net in ('ovirtmgmt', 'rhevm'):
                if 'bridge' in networks[net]:
                    mgmtIface = [networks[net]['bridge']]
                else:
                    mgmtIface = [networks[net]['iface']]
    except socket_error as err:
        if err.errno == errno.ECONNREFUSED:
            LOGGER.debug("Connection refused with VDSM", exc_info=True)
        elif err.errno == errno.ENETUNREACH:
            LOGGER.debug("Network is unreachable to reach VDSM", exc_info=True)
        else:
            LOGGER.error("Catching exception:", exc_info=True)
    except KeyError as err:
        LOGGER.error("Cannot collect network data!", exc_info=True)
    except Exception as err:
        if 'No permission to read file:' in str(err):
            LOGGER.debug("pem files not available yet!", exc_info=True)
        else:
            LOGGER.error("Catching exception:", exc_info=True)

    if cfg["server"] is not None and validate_server(cfg["server"]):
        cfg["server"], cfg["port"] = cfg["server"].split(":")

    if cfg["server"] is not None and cfg["server"] != "None" and \
            cfg["server"] != "":
        server_url = [unicode(info) for info in [cfg["server"],
                                                 cfg["port"]] if info]

        port, sslPort = compatiblePort(cfg["port"])
        if sslPort:
            proto = "https"
        else:
            proto = "http"

        engine_data = '"%s %s://%s"' % (
            config.engine_name,
            proto,
            ":".join(server_url)
        )

    if cfg['server'] == 'None' or cfg['server'] is None:
        cfg['server'] = ""
    if cfg['port'] == 'None':
        cfg['port'] = config.ENGINE_PORT

    # Update the /etc/defaults/ovirt file
    _hack_to_workaround_pyaug_issues(mgmtIface, cfg, engine_data)


class Plugin(plugins.NodePlugin):
    _cert_path = None
    _server = None
    _port = None
    _model = None

    def __init__(self, app):
        super(Plugin, self).__init__(app)
        self._model = {}
        sync_mgmt()

    def name(self):
        return config.engine_name

    def rank(self):
        return 100

    def model(self):
        cfg = VDSM().retrieve()
        model = {
            "vdsm_cfg.address": cfg["server"] or "",
            "vdsm_cfg.port": cfg["port"] or config.ENGINE_PORT,
            "vdsm_cfg.password": "",
            "check.fqdn": True
        }
        return model

    def validators(self):

        return {"vdsm_cfg.address": valid.Text() | valid.Empty(),
                "vdsm_cfg.port": valid.Port(),
                "vdsm_cfg.password": valid.Text(),
                }

    def ui_content(self):
        sync_mgmt()

        buttons = []
        net_is_configured = utils.network.NodeNetwork().is_configured()
        header_menu = "{engine_name} Configuration".format(
            engine_name=config.engine_name
        )

        if not net_is_configured:
            ws = [
                ui.Header(
                    "header[0]",
                    header_menu
                ),
                ui.Notice("network.notice",
                          "Networking is not configured, " +
                          "please configure it before " +
                          "registering"),
                ui.Divider("divider[0]")
            ]
        else:
            ws = [
                ui.Header(
                    "header[0]",
                    header_menu
                ),
                ui.Entry("vdsm_cfg.address",
                         str(config.engine_name) + " FQDN (or fqdn:port):"),
                ui.Label("nodefqdn",
                         "Note: Make sure you have configured"
                         " NODE FQDN first"),
                ui.Divider("divider[0]"),
                ui.Checkbox("check.fqdn", "Check Engine FQDN?", state=True),
                ui.Divider("divider[1]"),
                ui.Label("vdsm_cfg.password._label",
                         "Optional password for adding Node through " +
                         str(config.engine_name)),
                ui.Label("vdsm_cfg.password._label2",
                         "Note: Setting password will enable SSH daemon"),
                ui.ConfirmedEntry("vdsm_cfg.password", "Password:", True),
            ]
            buttons = [
                ui.SaveButton(
                    "action.register",
                    "Save & Register"
                )
            ]

        page = ui.Page("page", ws)
        page.buttons = buttons

        self.widgets.add(page)
        return page

    def on_change(self, changes):
        if changes.contains_any(["vdsm_cfg.password"]):
            self._model.update(changes)

    def on_merge(self, effective_changes):
        model = VDSM()
        changes = Changeset(self.pending_changes(False))
        effective_model = Changeset(self.model())
        effective_model.update(effective_changes)

        self.logger.debug("Changes: %s" % changes)
        self.logger.debug("Effective Model: %s" % effective_model)

        txs = utils.Transaction("Configuring {engine_name}".format(
            engine_name=config.engine_name))

        if changes.contains_any(["vdsm_cfg.password"]):
            txs += [SetRootPassword(
                password=effective_model["vdsm_cfg.password"]
            )]

        if effective_model["vdsm_cfg.address"]:
            if validate_server(effective_model["vdsm_cfg.address"]):
                self._server, self._port = \
                    effective_model["vdsm_cfg.address"].split(":")
            else:
                self._server = effective_model["vdsm_cfg.address"]
                self._port = config.ENGINE_PORT

            cfqdn = effective_model["check.fqdn"]
            self.logger.debug("DOUG cfqdn %s" % cfqdn)
            txs += [NodeRegister(self._server, self._port, cfqdn)]

        model.update(server=self._server, port=self._port)

        if len(txs) > 0:
            progress_dialog = ui.TransactionProgressDialog("dialog.txs", txs,
                                                           self)
            progress_dialog.run()

            # VDSM messes with logging, and we just reset it
            log.configure_logging()

        # Acts like a page reload
        return self.ui_content()


def compatiblePort(portNumber):
    """
    Until the version 3.0, oVirt Engine provided port 8443/8080 to oVirt Node
    download cert and others files. Since 3.1 the default port changed to
    443/80. This function, will return the compatible port in case the VDSM
    cannot communicate with oVirt Engine.

    :param portNumber: port which doesn't communicate with oVirt Engine
    :returns: compatible port number (or None if there is no compatible port)
              and if it's SSL port or not (bool)
    """

    compatPort = {
        '443': ('8443', True),
        '8443': ('443', True),
        '80': ('8080', False),
        '8080': ('80', False)
    }

    return compatPort.get(portNumber, (None, False))


#
# Functions and classes to support the UI
#
class VDSM(NodeConfigFileSection):
    """Class to handle VDSM configuration in /etc/default/ovirt file

    >>> from ovirt.node.config.defaults import ConfigFile, SimpleProvider
    >>> fn = "/tmp/cfg_dummy"
    >>> cfgfile = ConfigFile(fn, SimpleProvider)
    >>> n = VDSM(cfgfile)
    >>> n.update("engine.example.com", "1234", "p")
    >>> sorted(n.retrieve().items())
    [('cert_path', 'p'), ('port', '1234'), ('server', 'engine.example.com')]
    """
    keys = ("OVIRT_MANAGEMENT_SERVER",
            "OVIRT_MANAGEMENT_PORT",
            "OVIRT_MANAGEMENT_CERTIFICATE")

    @NodeConfigFileSection.map_and_update_defaults_decorator
    def update(self, server, port, cert_path):
        if validate_server(server):
            server, port = server.split(":")
        else:
            port = config.ENGINE_PORT

        (valid.Empty(or_none=True) | valid.Text())(server)
        (valid.Empty(or_none=True) | valid.Port())(port)


class NodeRegister(utils.Transaction.Element):
    title = "Registering oVirt Node..."

    def __init__(self, engine, port, check_fqdn):
        super(NodeRegister, self).__init__()
        self.engine = engine
        self.port = port

        if check_fqdn:
            self.check_fqdn = True
        else:
            self.check_fqdn = False

    def commit(self):
        out, ret = execute_cmd("vdsm-tool register --engine-fqdn {e} "
                               "--engine-https-port {p} "
                               "--ssh-user {s} "
                               "--check-fqdn {c}".format(e=self.engine,
                                                         p=self.port,
                                                         s="root",
                                                         c=self.check_fqdn))
        if ret != int("0"):
            msg = "{t}\n{l}".format(t=out.split("Traceback")[0],
                                    l="Full log: /var/log/vdsm/register.log")
            raise Exception(msg)


class SetRootPassword(utils.Transaction.Element):
    title = "Setting root password and starting sshd"

    def __init__(self, password):
        super(SetRootPassword, self).__init__()
        self.password = password

    def commit(self):
        passwd = utils.security.Passwd()
        passwd.set_password("root", self.password)

        sshcfg = SSH()
        sshcfg.update(pwauth=True)
        sshcfg.commit()
