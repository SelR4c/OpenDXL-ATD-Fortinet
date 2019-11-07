#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Description: Python script to quarantine a host in the security fabric
# Date: 07 nov 2019
# Authors: Charles Prevot at Fortinet Paris
# Requirements: pip install requests

import requests
import json

requests.packages.urllib3.disable_warnings()

def getError(code: int):
    if code == 200:
        return
    elif code == 401:
        raise Exception("401 Unauthorized")
    elif code == 403:
        raise Exception("403 Forbidden")
    elif code == 404:
        raise Exception("404 Not Found")
    elif code == 500:
        raise Exception("500 Internal Server Error")
    else:
        raise Exception("Unknown Error " + str(code))

class Fortigate(object):

    def __init__(self, fgt_ip, port, token, vdom="root", verify=False):
        self.ip = fgt_ip # IP or Hostname FortiGate
        self.port = port # Administrative port for https
        self.token = token # API token

        self.url = "https://{}:{}".format(self.ip, str(self.port))
        self.headers = {"Authorization": "Bearer " + self.token}
        self.vdom = vdom

        self.verify = verify

    def add_quarantine(self, quarantine_host):
        data = {
            "ip_addresses": [ str(quarantine_host) ],
            "expiry": 0
        }
        res = requests.post(self.url + '/api/v2/monitor/user/banned/add_users',
            headers=self.headers, data=json.dumps(data), params={"vdom": self.vdom}, verify=self.verify)
        return res


def main():
    fgt = Fortigate("10.200.3.1", 1443, "cjk8f01gs0037j06djjckskkG55GGh")

    try:
        response = fgt.add_quarantine("192.168.1.10")
        getError(response.status_code)
    except Exception as e:
        print(e.args[1])
        return 1

    print("Successfully added address")
    return 0


if __name__ == "__main__":
    main()