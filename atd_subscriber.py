#!/usr/bin/env python

import logging
import os
import sys
import time
import json

from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Event, Request

logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

CONFIG_FILE = "Path To Config File"
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

with DxlClient(config) as client:

    client.connect()

    class MyEventCallback(EventCallback):
        def on_event(self, event):
            try:
                query = event.payload.decode()
                query = query[:query.rfind('}')+1]
                query = json.loads(query)

                # Get Destination IP and push to Fortinet
                ips = query['Summary']['Dst IP']
                if ips:
                    ipv4 = ips
                    print(ipv4)
                    os.system('python forti_push.py ' + ipv4)

                # Get IPs and push to Fortinet
                for ips in query['Summary']['Ips']:
                    if ipv4:
                        ipv4 = ips['Ipv4']
                        print (ipv4)
                        os.system('python forti_push.py ' + ipv4)

            except Exception as e:
                print(e)

        @staticmethod
        def worker_thread(req):
            client.sync_request(req)

    # Register the callback with the client
    client.add_event_callback('#', MyEventCallback(), subscribe_to_topic=False)
    client.subscribe("/mcafee/event/atd/file/report")

    # Wait forever
    while True:
       time.sleep(60)
