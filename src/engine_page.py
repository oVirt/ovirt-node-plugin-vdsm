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
import socket

from . import config
from distutils.util import strtobool
from socket import error as socket_error

from ovirt.node import plugins, valid, ui, utils, log
from ovirt.node.config.defaults import NodeConfigFileSection, SSH
from ovirt.node.plugins import Changeset
from ovirt.node.utils import process

from vdsm import vdscli

"""
Configure Engine
"""


LOGGER = log.getLogger(__name__)


def validate_server(server):
    """Validate server str if user provided ':' port schema"""
    return bool(server and ":" in server)


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
           cfg["mserver"])
    ag.set("/files/etc/default/ovirt/OVIRT_MANAGEMENT_PORT", "\"%s\"" %
           cfg["mport"])

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
    cfg = NodeManagement().retrieve()

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

    if cfg["mserver"] is not None and validate_server(cfg["mserver"]):
        cfg["mserver"], cfg["mport"] = cfg["mserver"].split(":")

    if cfg["mserver"] is not None and cfg["mserver"] != "None" and \
            cfg["mserver"] != "":
        server_url = [unicode(info) for info in [cfg["mserver"],
                                                 cfg["mport"]] if info]

        port, sslPort = compatiblePort(cfg["mport"])
        if sslPort:
            proto = "https"
        else:
            proto = "http"

        engine_data = '"%s %s://%s"' % (
            config.engine_name,
            proto,
            ":".join(server_url)
        )

    if cfg['mserver'] == 'None' or cfg['mserver'] is None:
        cfg['mserver'] = ""
    if cfg['mport'] == 'None':
        cfg['mport'] = config.ENGINE_PORT

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
        cfg = NodeManagement().retrieve()
        model = {
            "vdsm_cfg.address": cfg["mserver"] or "",
            "vdsm_cfg.port": cfg["mport"] or config.ENGINE_PORT,
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

        elif self._hosted_engine_configured():
            ws = [
                ui.Header(
                    "header[0]",
                    header_menu
                ),
                ui.Notice("he.notice",
                          "Hosted Engine is configured. Engine registration "
                          "is disabled, as this host is already registered to"
                          " the hosted engine"),
                ui.Divider("divider[0]"),

                ui.Label("vdsm_cfg.password._label",
                         "Password for adding additional hosts"),
                ui.Label("vdsm_cfg.password._label2",
                         "Note: This sets the root password and "
                         "enables SSH"),
                ui.ConfirmedEntry("vdsm_cfg.password", "Password:", True),
                ]

            buttons = [
                ui.SaveButton(
                    "action.register",
                    "Save"
                )
            ]

        else:
            ws = [
                ui.Header(
                    "header[0]",
                    header_menu
                ),
                ui.Entry("vdsm_cfg.address",
                         str(config.engine_name) + " FQDN (or fqdn:port):"),
                ui.Divider("divider[0]"),
                ui.Label("vdsm_cfg.password._label",
                         "Optional password for adding Node through " +
                         str(config.engine_name)),
                ui.Label("vdsm_cfg.password._label2",
                         "Note: This sets the root password and "
                         "enables SSH"),
                ui.ConfirmedEntry("vdsm_cfg.password", "Password:", True),
            ]
            buttons = [
                ui.SaveButton(
                    "action.register",
                    "Save / Register"
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
        model = NodeManagement()
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

            txs += [NodeRegister(self._server, self._port)]

        model.update(mserver=self._server, mport=self._port)

        if len(txs) > 0:
            progress_dialog = ui.TransactionProgressDialog("dialog.txs", txs,
                                                           self)
            progress_dialog.run()

            # VDSM messes with logging, and we just reset it
            log.configure_logging()

        # Acts like a page reload
        return self.ui_content()

    def _hosted_engine_configured(self):
        try:
            return self.application.plugins()["Hosted Engine"]._configured()
        except KeyError:
            self.logger.debug("Can't import hosted engine configuration data. "
                              "Is hosted engine installed/supported on this "
                              "version?")
            return False
        except:
            self.logger.exception("There was a problem querying the hosted "
                                  "engine configuration status. ",
                                  exc_info=True)
            return False


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
class NodeManagement(NodeConfigFileSection):
    """
    Return the below keys from /etc/default/ovirt
        OVIRT_MANAGEMENT_SERVER
        OVIRT_MANAGEMENT_PORT
        OVIRT_MANAGEMENT_CERTIFICATE
        OVIRT_MANAGEMENT_SERVER_FINGERPRINT
    """
    keys = ("OVIRT_MANAGEMENT_SERVER",
            "OVIRT_MANAGEMENT_PORT",
            "OVIRT_MANAGEMENT_CERTIFICATE",
            "OVIRT_MANAGEMENT_SERVER_FINGERPRINT",)

    @NodeConfigFileSection.map_and_update_defaults_decorator
    def update(self, mserver, mport, cert_path, fprint):
        if validate_server(mserver):
            mserver, mport = mserver.split(":")
        else:
            mport = config.ENGINE_PORT

        (valid.Empty(or_none=True) | valid.Text())(mserver)
        (valid.Empty(or_none=True) | valid.Port())(mport)

    def retrieve(self):
        cfg = dict(NodeConfigFileSection.retrieve(self))

        # Replace the string 'None' to None type
        for item in cfg:
            if cfg[item] == 'None':
                cfg[item] = None

        if cfg['mserver'] is not None and ":" in cfg['mserver']:
            cfg['mserver'], cfg['mport'] = cfg['mserver'].split(":")

        return cfg


class RegistrationTriggered(NodeConfigFileSection):
    """
    Return OVIRT_NODE_REGISTER value from /etc/default/ovirt
    via retrieve() or update this value via update() if
    registration was triggered
    """
    keys = ("OVIRT_NODE_REGISTER",)

    @NodeConfigFileSection.map_and_update_defaults_decorator
    def update(self, node_register):
        valid.Boolean()(node_register)
        return {"OVIRT_NODE_REGISTER": "True" if node_register else None}

    def retrieve(self):
        cfg = dict(NodeConfigFileSection.retrieve(self))
        try:
            if cfg['node_register'] is not None:
                return strtobool(cfg['node_register'])
        except ValueError:
            LOGGER.error("OVIRT_NODE_REGISTER must be a bool!")

        return False


class NodeRegister(utils.Transaction.Element):
    title = "Registering oVirt Node..."

    def __init__(self, engine, port):
        super(NodeRegister, self).__init__()
        self.engine = engine
        self.port = port

    def commit(self):
        try:
            process.check_output(['vdsm-tool', 'register',
                                  '--engine-fqdn', self.engine,
                                  '--node-name', socket.gethostname(),
                                  '--engine-https-port', self.port,
                                  '--ssh-user', 'root',
                                  '--check-fqdn', 'False'])
        except process.CalledProcessError as e:
            msg_users = ""
            if "No route to host" in e.output:
                msg_users = "No route to host {0}".format(self.engine)

            elif "Connection refused" in e.output:
                msg_users = "Connection refused to {0}".format(self.engine)

            elif "http response was non OK, code 400" in e.output:
                msg_users = "http response was non OK, code 400.\n" \
                            "Have you tried to add into the datacenter an " \
                            "existing hypervisor?"
            else:
                msg_users = e.output

            msg = "{err} {engineaddr}!\n{output_cmd}\n{full_log}".format(
                err='Cannot register the node into',
                engineaddr=self.engine,
                output_cmd=msg_users,
                full_log="Full log: /var/log/vdsm/register.log"
            )
            raise Exception(msg)

        # Registration triggered with success, set OVIRT_NODE_REGISTER
        RegistrationTriggered().update(True)


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
