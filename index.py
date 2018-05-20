#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import logging
import os
from traceback import format_exc

from sanji.connection.mqtt import Mqtt
from sanji.core import Sanji
from sanji.core import Route

from voluptuous import All, Any, Length, Match, Range, Required, Schema
from voluptuous import REMOVE_EXTRA, Optional, In

from cellular.manager import Manager


class Index(Sanji):
    _logger = logging.getLogger("sanji.cellular.index")

    CONF_PROFILE_SCHEMA = Schema(
        {
            Required("apn", default="internet"):
                All(Any(unicode, str), Length(0, 100)),
            Optional("type", default="ipv4v6"):
                In(frozenset(["ipv4", "ipv6", "ipv4v6"])),
            Optional("auth", default={}): {
                Required("protocol", default="none"):
                    In(frozenset(["none", "chap", "pap", "both"])),
                Optional("username"):
                    All(Any(unicode, str), Length(0, 255)),
                Optional("password"):
                    All(Any(unicode, str), Length(0, 255))
            }
        },
        extra=REMOVE_EXTRA)

    CONF_SCHEMA = Schema(
        {
            "id": int,
            Required("enable"): bool,
            Required("pdpContext"): {
                Required("static"): bool,
                Required("id"): int,
                Required("retryTimeout", default=120): All(
                    int,
                    Any(0, Range(min=10, max=86400 - 1))
                ),
                Required("primary"): CONF_PROFILE_SCHEMA,
                Required("secondary", default={}): CONF_PROFILE_SCHEMA
            },
            Required("pinCode", default=""): Any(Match(r"[0-9]{4,8}"), ""),
            Required("keepalive"): {
                Required("enable"): bool,
                Required("targetHost"): basestring,
                Required("intervalSec"): All(
                    int,
                    Any(0, Range(min=60, max=86400 - 1))
                ),
                Required("reboot",
                         default={"enable": False, "cycles": 1}): {
                    Required("enable", default=False): bool,
                    Required("cycles", default=1): All(
                        int,
                        Any(0, Range(min=1, max=48))),
                }
            }
        },
        extra=REMOVE_EXTRA)

    def init(self, *args, **kwargs):
        path_root = os.path.abspath(os.path.dirname(__file__))
        self._mgr = Manager(
            name="cellular",
            path=path_root,
            update_network_info_callback=self._publish_network_info)

    @Route(methods="get", resource="/network/cellulars")
    def get_all(self, message, response):
        if self._mgr is None:
            return response(code=200, data=[])

        return response(code=200, data=self._mgr.getAll())

    @Route(methods="get", resource="/network/cellulars/:id")
    def get(self, message, response):
        id_ = int(message.param["id"])
        try:
            data = self._mgr.get(id_)
        except:
            self._logger.warning(format_exc())
            return response(code=400, data={"message": "resource not exist"})

        return response(code=200, data=data)

    PUT_SCHEMA = CONF_SCHEMA

    @Route(methods="put", resource="/network/cellulars/:id", schema=PUT_SCHEMA)
    def put(self, message, response):
        id_ = int(message.param["id"])

        # _logger.info(str(message.data))

        data = Index.PUT_SCHEMA(message.data)
        data["id"] = id_

        self._logger.info(str(data))

        # APN will be modified if static specified;
        # otherwise only retrive APN from given id
        # ** always use the 1st PDP context for static
        # TODO: Verizon is using 3rd PDP context
        if data["pdpContext"]["static"] is True:
            data["pdpContext"]["id"] = 1

        resp = self._mgr.update(id=id_, newObj=data)

        return response(code=200, data=resp)

    def _publish_network_info(self, nwk_info):
        data = {
            "name": nwk_info.alias,
            "actualIface": nwk_info.devname if nwk_info.devname else "",
            "wan": True,
            "type": "cellular",
            "mode": "dhcp",
            "status": True if nwk_info.status == "connected" else False,
            "ip": nwk_info.ip,
            "netmask": nwk_info.netmask,
            "gateway": nwk_info.gateway,
            "dns": nwk_info.dns_list
        }
        self._logger.info("publish network info: " + str(data))
        self.publish.event.put("/network/interfaces/{}".format(nwk_info.alias),
                               data=data)

    @Route(methods="get", resource="/network/cellulars/:id/firmware")
    def get_fw(self, message, response):
        m_info = self._mgr._cell_mgmt.module_info()
        if m_info.module != "MC7354":
            return response(code=200, data={
                "switchable": False,
                "current": None,
                "preferred": None,
                "avaliable": None
            })

        fw_info = self._mgr._cell_mgmt.get_cellular_fw()
        return response(code=200, data=fw_info)

    @Route(methods="put", resource="/network/cellulars/:id/firmware")
    def put_fw(self, message, response):
        response(code=200)

        self._mgr._cell_mgmt.set_cellular_fw(
            fwver=message.data["fwver"],
            config=message.data["config"],
            carrier=message.data["carrier"]
        )


if __name__ == "__main__":
    FORMAT = "%(asctime)s - %(levelname)s - %(lineno)s - %(message)s"
    logging.basicConfig(level=logging.INFO, format=FORMAT)
    cellular = Index(connection=Mqtt())
    cellular.start()
