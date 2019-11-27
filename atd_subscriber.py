#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Description: Python script to quarantine a host in the security fabric. IP will be visible in menu Monitor > Quarantine Monitor.
# Date: 27 nov 2019
# Authors: Charles Prevot at Fortinet Paris - inspired by mohlcyber https://github.com/mohlcyber/OpenDXL-ATD-Fortinet
# Requirements: pip install requests dxlclient

import argparse
import json
import logging
import sys
import time

from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Event, Request

from forti_add_quarantine import Fortigate, getError

logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

CONFIG_FILE = "Path To Config File"
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

def fetch_dxlclient(fgt):
    with DxlClient(config) as client:
        client.connect()

        class MyEventCallback(EventCallback):
            def on_event(self, event):
                try:
                    query = event.payload.decode()
                    query = query[:query.rfind('}') + 1]
                    query = json.loads(query)

                    # Get Destination IP and push to Fortinet
                    ips = query['Summary']['Dst IP']
                    if ips:
                        ipv4 = ips
                        logger.debug("Destination IPv4 fetch from OpenDXL:" + ipv4)
                        response = fgt.add_quarantine([ ipv4 ]) # list
                        getError(response.status_code)

                    # Get IPs and push to Fortinet
                    ips = query['Summary']['Ips']
                    if ips:
                        logger.debug("IPs v4 fetch from OpenDXL:" + str(ips))
                        response = fgt.add_quarantine(ips) # list
                        getError(response.status_code)

                except Exception as e:
                    logger.error(str(e.args))
                    return 1

            @staticmethod
            def worker_thread(req):
                client.sync_request(req)

        # Register the callback with the client
        client.add_event_callback('#', MyEventCallback(), subscribe_to_topic=False)
        client.subscribe("/mcafee/event/atd/file/report")

        # Wait forever
        while True:
            time.sleep(60)


def main():
    parser = argparse.ArgumentParser(description='This integration is focusing on the automated threat response with McAfee ATD, OpenDXL and Fortinet Firewalls.')
    parser.add_argument('-i', '--ip', help='FortiGate IP', required=True)
    parser.add_argument('-t', '--token', help='FortiGate Token', required=True)
    parser.add_argument('-p', '--port', help='FortiGate administrative port', default=443)

    args = parser.parse_args()
    fgt = Fortigate(str(args.ip), int(args.port), str(args.token))
    return fetch_dxlclient(fgt)

if __name__ == "__main__":
    main()
