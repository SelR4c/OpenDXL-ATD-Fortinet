#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Description: Python script to quarantine a host in the security fabric. IP will be visible in menu Monitor > Quarantine Monitor.
# Date: 07 nov 2019
# Update: 27 nov 2019
# Authors: Charles Prevot at Fortinet Paris
# Requirements: pip install requests

import argparse
import json

import requests

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

    def __init__(self, fgt_ip, port, token, vdom="root", verify=False, timeout=10):
        self.ip = fgt_ip # IP or Hostname FortiGate
        self.port = port # Administrative port for https
        self.token = token # API token

        self.url = "https://{ip}:{port}".format(ip=self.ip, port=str(self.port))
        self.headers = {"Authorization": "Bearer " + self.token}
        self.vdom = vdom

        self.verify = verify
        self.timeout = timeout

    # function add_quarantine()
    # description: add an IP address to quarantine user in FortiOS. Quarantine user will be shared across security fabric.
    # parameters:
    #   - quarantine_host: list of ip address of the host to quarantine
    #   - expiry: time to ban in second. 0 = unlimited time
    def add_quarantine(self, quarantine_host: list, expiry=0):
        try:
            data = {
                "ip_addresses": quarantine_host,
                "expiry": expiry
            }
            res = requests.post(self.url + '/api/v2/monitor/user/banned/add_users',
                headers=self.headers, data=json.dumps(data), params={"vdom": self.vdom}, timeout=self.timeout, verify=self.verify)
        except:
            raise

        return res

# Standalone usage, only one ip address
def main():
    parser = argparse.ArgumentParser(description='Quarantine a host in the security fabric')
    parser.add_argument('-i', '--ip', help='FortiGate IP', required=True)
    parser.add_argument('-t', '--token', help='FortiGate Token', required=True)
    parser.add_argument('-p', '--port', help='FortiGate administrative port', default=443)
    parser.add_argument('-q', '--quarantine', help='Host to ban', required=True)

    args = parser.parse_args()

    fgt = Fortigate(str(args.ip), int(args.port), str(args.token))

    try:
        response = fgt.add_quarantine([ str(args.quarantine) ])
        getError(response.status_code)
    except Exception as e:
        print(str(e.args))
        return 1

    print("Successfully added quarantine host. See https://{fgt_ip}:{port}/ng/user/quarantine".format(fgt_ip=args.ip, port=args.port))
    return 0

if __name__ == "__main__":
    main()
