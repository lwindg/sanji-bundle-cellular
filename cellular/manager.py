#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import logging
import os
import copy
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
            "initThread": [thread object],
            "cellmgmt": [cell_mgmt object]
        }
        """
        self._cellulars = []
        for module in super(Manager, self).getAll():
            cellular = {"id": module["id"], "conf": module}
            _init_thread = Thread(
                name="sanji.cellular.{}.init_thread".format(module["id"]),
                target=self.__initial_procedure,
                args=(cellular,))
            _init_thread.daemon = True
            _init_thread.start()
            cellular["initThread"] = _init_thread
            self._cellulars.append(cellular)

    def __init_cellular(self, cellular=None):
        conf = cellular["conf"]
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

        cellular["devname"] = devname
        cellular["cellmgmt"] = cell_mgmt
        self.__init_cellular(cellular)

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
        cellular["manager"] = _mgr

        # clear PIN code if pin error
        if _mgr.status() == Cellular.Status.pin_error and pin != "":
            conf["pinCode"] = ""
            self.model.save_db()

        _mgr.set_update_network_information_callback(
            self._publish_network_info)

        _mgr.start()

    def __init_completed(self, obj=None):
        if not obj or \
                not obj["manager"] or \
                obj["manager"].status() == Cellular.Status.switching_carrier:
            return False

        if obj.get("initThread", None) is None:
            return True

        obj["initThread"].join(0)
        if obj["initThread"].is_alive():
            return False

        obj["initThread"] = None
        return True

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

    def _get_obj_by_id(self, id):
        for cellular in self._cellulars:
            if cellular["id"] == id:
                return cellular
        return None

    def _get_data_by_obj(self, obj):
        _mgr = obj["manager"]

        try:
            obj["vnstat"].update()
            _usage = obj["vnstat"].get_usage()
        except:
            _usage = {
                "txkbyte": -1,
                "rxkbyte": -1
            }

        status = _mgr.status()
        minfo = _mgr.module_information()
        sinfo = _mgr.sim_information()
        cinfo = _mgr.cellular_information()
        ninfo = _mgr.network_information()

        data = copy.deepcopy(obj["conf"])
        data["pdpContext"]["list"] = minfo.pdp_context_list
        data["status"] = status.name
        data["name"] = ninfo.alias
        data["mode"] = "" if cinfo is None else cinfo.mode
        data["signal"] = {"csq": 0, "rssi": 0, "ecio": 0.0} if cinfo is None \
            else {"csq": cinfo.signal_csq,
                  "rssi": cinfo.signal_rssi_dbm,
                  "ecio": cinfo.signal_ecio_dbm}
        data["operatorName"] = "" if cinfo is None else cinfo.operator
        data["lac"] = "" if cinfo is None else cinfo.lac
        data["tac"] = "" if cinfo is None else cinfo.tac
        data["nid"] = "" if cinfo is None else cinfo.nid
        data["cellId"] = "" if cinfo is None else cinfo.cell_id
        data["bid"] = "" if cinfo is None else cinfo.bid
        data["imsi"] = "" if sinfo is None else sinfo.imsi
        data["iccId"] = "" if sinfo is None else sinfo.iccid
        data["pinRetryRemain"] = (
                -1 if sinfo is None else sinfo.pin_retry_remain)
        data["imei"] = "" if minfo is None else minfo.imei
        data["esn"] = "" if minfo is None else minfo.esn
        data["mac"] = "00:00:00:00:00:00" if minfo is None else minfo.mac
        data["ip"] = "" if ninfo is None else ninfo.ip
        data["netmask"] = "" if ninfo is None else ninfo.netmask
        data["gateway"] = "" if ninfo is None else ninfo.gateway
        data["dns"] = [] if ninfo is None else ninfo.dns_list
        data["usage"] = _usage
        return data

    def get(self, id):
        cellular = self._get_obj_by_id(id)
        if not cellular or not self.__init_completed(obj=cellular):
            raise ValueError("invalid cellular ID {}".format(id))
        return self._get_data_by_obj(cellular)
        # return super(Manager, self).get(id=id)

    def getAll(self):
        data = []
        for cellular in self._cellulars:
            if not self.__init_completed(obj=cellular):
                continue
            data.append(self._get_data_by_obj(cellular))
        return data
        # return super(Manager, self).getAll()

    def update(self, id, newObj):
        cellular = self._get_obj_by_id(id)
        if not cellular or not self.__init_completed(obj=cellular):
            raise ValueError("invalid cellular ID {}".format(id))

        cellular["conf"] = newObj
        cellular["manager"].stop()

        self.__init_cellular(cellular)
        return super(Manager, self).update(id, newObj)

    def get_fw(self, id):
        cellular = self._get_obj_by_id(id)
        if not cellular or not self.__init_completed(obj=cellular):
            raise ValueError("invalid cellular ID {}".format(id))
        try:
            fw_info = cellular["cellmgmt"].get_cellular_fw()
        except:
            return {
                "switchable": False,
                "current": None,
                "preferred": None,
                "avaliable": None
            }
        return fw_info

    def update_fw(self, id, **kwargs):
        cellular = self._get_obj_by_id(id)
        if not cellular or not self.__init_completed(obj=cellular):
            raise ValueError("invalid cellular ID {}".format(id))

        if cellular["manager"] is not None:
            cellular["manager"].stop()
            cellular["manager"]._status = Cellular.Status.switching_carrier

        try:

            cellular["cellmgmt"].set_cellular_fw(
                kwargs.pop("carrier"), **kwargs)
        except:
            self._logger.warning("switch carrier failed: " + format_exc())

        self.__init_cellular(cellular)


if __name__ == "__main__":
    FORMAT = "%(asctime)s - %(levelname)s - %(lineno)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=FORMAT)
    _logger = logging.getLogger("sanji.cellular.manager")

    path_root = os.path.abspath(os.path.dirname(__file__)+"/..")
    manager = Manager(name="cellular", path=path_root)

    import time
    while True:
        time.sleep(1)
