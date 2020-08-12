#
# This file is part of PCAP BGP Parser (pbgpp)
#
# Copyright 2016-2017 DE-CIX Management GmbH
# Author: Tobias Hannaske <tobias.hannaske@de-cix.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import struct
import logging
from binascii import hexlify

from pbgpp.PCAP.Information import PCAPLayer2Information


class PCAPEthernet:
  
    ETH_TYPE_IPV4 = 0x0800
    ETH_TYPE_IPV6 = 0x86DD
    
    ETH_TYPE_VLAN = 0x8100  # Vlan
    ETH_TYPE_QINQ = 0x88a8  # QinQ
    
    BITMASK_VLAN_ID_LENGTH = 0x0FFF

    def __init__(self, payload):
        self.payload = payload
        self.type = None
        self.mac = None
        self.vlan_tags = [None, None] # [802.1q, 802.1ad]

        self.parsing_error = False
        self.parsed = False
        self.payload_offset = 14 # default if there are no vlan tags

        self.__parse()

    def __parse(self):
        try:
            self.parsed = True

            # Ethernet type
            self.type = struct.unpack("!H", self.payload[12:14])[0]

            if self.type == PCAPEthernet.ETH_TYPE_VLAN:
                self.vlan_tags[0] = struct.unpack("!H", self.payload[14:16])[0] & 0x0FFF #last 12 bits are vlan id
                self.payload_offset = 16
                
            if self.type == PCAPEthernet.ETH_TYPE_QINQ:
                self.vlan_tags[0] = struct.unpack("!H", self.payload[18:20])[0] & BITMASK_VLAN_ID_LENGTH
                self.vlan_tags[1] = struct.unpack("!H", self.payload[14:16])[0] & BITMASK_VLAN_ID_LENGTH
                self.payload_offset = 20

            # MAC addresses
            self.mac = PCAPLayer2Information(self.payload[6:12], self.payload[:6], self.vlan_tags)

        except Exception as e:
            logging.error("Parsing ethernet frame caused exception (message: " + str(e) + ")")
            self.parsing_error = True

    def get_type(self):
        return self.type

    def get_mac(self):
        return self.mac

    def get_service_vlan(self):
        return self.vlan_tags[1]

    def get_customer_vlan(self):
        return self.vlan_tags[0]

    def get_payload(self):
        return self.payload

    def get_eth_payload(self): 
        return self.payload[self.payload_offset:] 

    def __str__(self):
        if self.parsed:
            if not self.parsing_error:
                # Preparing information
                type = hexlify(self.payload[12:14]).decode("utf-8")
                length = len(self)
                source = self.get_mac().get_source_string()
                destination = self.get_mac().get_destination_string()

                # and return formatted output
                return "<Ethernet type={0} length={1} source={2} destination={3}>".format(type, length, source, destination)
            else:
                logging.debug("Returning string representation of malformed ethernet frame")
                return "<MalformedEthernet length={0}>".format(len(self.payload))
        else:
            logging.debug("Returning string representation of not yet parsed ethernet frame")
            return "<Ethernet type=UNKNOWN length=UNKNOWN source=UNKNOWN destination=UNKNOWN>"

    def __len__(self):
        # len(obj) should represent the length of the payload
        if self.parsed and not self.parsing_error:
            return len(self.payload)
        else:
            logging.debug("Returning zero-length due to malformed or not yet parsed ethernet frame")
            return 0

    def __eq__(self, other):
        # Compare the exact byte payload to determine if an ethernet packet equals another one
        if self.payload == other.payload:
            return True
        else:
            return False
