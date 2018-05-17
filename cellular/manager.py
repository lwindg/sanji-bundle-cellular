#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import logging
import os
from threading import Thread
from traceback import format_exc

from sanji.model import Model

from cell_mgmt import CellMgmt, CellMgmtError
from cell_mgmt import CellAllModuleNotSupportError
from cellular import Cellular
from vnstat import VnStat  # , VnStatError

from sh import rm, service

_logger = logging.getLogger("sanji.cellular")


class Manager(Model):
    _logger = logging.getLogger("sanji.cellular.manager")

    def __init__(self, *args, **kwargs):
        self._path = kwargs["path"]
        self._publish_network_info = \
            kwargs.pop("update_network_info_callback", None)
        super(Manager, self).__init__(*args, **kwargs)

        self.__init_monit_config(
            enable=(self.model.db[0]["enable"] and
                    self.model.db[0]["keepalive"]["enable"] and True and
                    self.model.db[0]["keepalive"]["reboot"]["enable"] and
                    True),
            target_host=self.model.db[0]["keepalive"]["targetHost"],
            iface="",
            cycles=self.model.db[0]["keepalive"]["reboot"]["cycles"]
        )

        """
        cellular: {
            "id": <module id>,
            "conf": <configs for the module>,
            "devname": [device node],
            "vnstat": [vnstat object],
            "manager": [manager object],
            "initThread": [thread object]
        }
        """
        self._cellulars = []
        for module in self.getAll():
            cellular = {"id": module["id"], "conf": module}
            _init_thread = Thread(
                name="sanji.cellular.{}.init_thread".format(module["id"]),
                target=self.__initial_procedure,
                args=(cellular,))
            _init_thread.daemon = True
            _init_thread.start()
            cellular["initThread"] = _init_thread
            self._cellulars.append(cellular)

    def __initial_procedure(self, cellular=None):
        """
        Continuously check Cellular modem existence.
        Set self._dev_name, self._mgr, self._vnstat properly.
        """
        cell_mgmt = CellMgmt(slot=cellular["id"])
        devname = None

        for retry in xrange(0, 4):
            if retry == 3:
                return

            try:
                devname = cell_mgmt.module_info().devname
                break
            except CellAllModuleNotSupportError:
                return
            except CellMgmtError:
                _logger.warning("get module failure: " + format_exc())
                cell_mgmt.power_cycle(timeout_sec=60)

        conf = cellular["conf"]
        cellular["devname"] = devname
        self.__init_monit_config(
            enable=(conf["enable"] and
                    conf["keepalive"]["enable"] and True and
                    conf["keepalive"]["reboot"]["enable"] and
                    True),
            target_host=conf["keepalive"]["targetHost"],
            iface=cellular["devname"],
            cycles=conf["keepalive"]["reboot"]["cycles"]
        )
        self.__create_cellulard(cellular)

        if not devname and devname != "":
            cellular["vnstat"] = VnStat(devname)

    def __create_cellulard(self, cellular):
        conf = cellular["conf"]
        pin = conf["pinCode"]
        pdp_context_list = []
        _default_pdpc = {
            "apn": "internet",
            "type": "ipv4v6",
            "auth": {
                "protocol": "none",
                "username": "",
                "password": ""
            }
        }
        if "primary" in conf["pdpContext"]:
            pdpc = {
                "apn": conf["pdpContext"]["primary"].get("apn", "internet"),
                "type": conf["pdpContext"]["primary"].get("type", "ipv4v6"),
                "auth": conf["pdpContext"]["primary"].get(
                    "auth", _default_pdpc["auth"])
            }
        else:
            pdpc = _default_pdpc.copy()
        pdp_context_list.append(pdpc)
        if "secondary" in conf["pdpContext"]:
            pdpc = {
                "apn": conf["pdpContext"]["secondary"].get("apn", "internet"),
                "type": conf["pdpContext"]["secondary"].get("type", "ipv4v6"),
                "auth": conf["pdpContext"]["secondary"].get(
                    "auth", _default_pdpc["auth"])
            }
        else:
            pdpc = _default_pdpc.copy()
        pdp_context_list.append(pdpc)

        _mgr = Cellular(
            slot=cellular["id"],
            dev_name=cellular["devname"],
            enabled=conf["enable"],
            pin=None if pin == "" else pin,
            static_pdp_context=conf["pdpContext"].get("static", True),
            pdp_context_id=conf["pdpContext"].get("id", 1),
            pdp_context_list=pdp_context_list,
            pdp_context_retry_timeout=conf["pdpContext"]["retryTimeout"],
            keepalive=conf["keepalive"],
            log_period_sec=60)
        cellular["mamager"] = _mgr

        # clear PIN code if pin error
        if _mgr.status() == Cellular.Status.pin_error and pin != "":
            conf["pinCode"] = ""
            self.model.save_db()

        _mgr.set_update_network_information_callback(
            self._publish_network_info)

        _mgr.start()

    def __init_completed(self, id=1):
        for cellular in self._cellulars:
            if cellular["id"] != id:
                continue

            if cellular.get("initThread", None) is None:
                return True

            cellular["initThread"].join(0)
            if cellular["initThread"].is_alive():
                return False

            cellular["initThread"] = None
            return True
        return False

    def __init_monit_config(
            self, enable=False, target_host="8.8.8.8", iface="", cycles=1):
        if enable is False:
            rm("-rf", "/etc/monit/conf.d/keepalive")
            service("monit", "restart")
            return

        ifacecmd = "" if iface == "" or iface is None \
                   else "-I {}".format(iface)
        config = """check program ping-test with path "/bin/ping {target_host} {ifacecmd} -c 3 -W 20"
    if status != 0
    then exec "/bin/bash -c '/usr/sbin/cell_mgmt power_off force && /bin/sleep 5 && /sbin/reboot -i -f -d'"
    every {cycles} cycles
"""  # noqa
        with open("/etc/monit/conf.d/keepalive", "w") as f:
            f.write(config.format(
                target_host=target_host, ifacecmd=ifacecmd, cycles=cycles))
        service("monit", "restart")


if __name__ == "__main__":
    FORMAT = "%(asctime)s - %(levelname)s - %(lineno)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=FORMAT)
    _logger = logging.getLogger("sanji.cellular.manager")

    path_root = os.path.abspath(os.path.dirname(__file__)+"/..")
    manager = Manager(name="cellular", path=path_root)

    import time
    while True:
        time.sleep(1)
