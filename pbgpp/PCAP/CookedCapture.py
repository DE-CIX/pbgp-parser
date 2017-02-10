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


class PCAPCookedCapture:
    ETH_TYPE_IPV4 = 0x0800

    SLL_SENT_TO_US = 0x0000
    SLL_BROADCAST = 0x0001
    SLL_MULTICAST = 0x0002
    SLL_SENT_TO_THIRD_PARTY = 0x0003
    SLL_SENT_BY_US = 0x0004

    SLL_ALLOWED_VALUES = [SLL_SENT_TO_US, SLL_BROADCAST, SLL_MULTICAST, SLL_SENT_TO_THIRD_PARTY, SLL_SENT_BY_US]

    def __init__(self, payload):
        self.payload = payload

        # SLL Packet Type
        self.packet_type = None

        # Ethernet Type
        self.type = None

        # Set of MAC addresses (destination address is always None)
        self.mac = None

        # Link Layer address length
        self.address_length = None

        self.parsing_error = False
        self.parsed = False

        self.__parse()

    def __parse(self):
        try:
            self.parsed = True

            # Packet type
            self.packet_type = struct.unpack("!H", self.payload[0:2])[0]
            if self.packet_type not in self.SLL_ALLOWED_VALUES:
                raise Exception("SLL packet type does not match allowed SLL packet type values.")

            self.address_length = struct.unpack("!H", self.payload[4:6])[0]
            if self.address_length is not 6:
                raise Exception("SLL address length does not equal 6 (which means we don't got a MAC address here)")

            # MAC addresses
            self.mac = PCAPLayer2Information(self.payload[6:12], None)

            # IP Type
            self.type = struct.unpack("!H", self.payload[14:16])[0]

        except Exception as e:
            logging.error("Parsing SLL frame caused exception (message: " + e.message + ")")
            self.parsing_error = True

    def get_type(self):
        return self.type

    def get_mac(self):
        return self.mac

    def get_payload(self):
        return self.payload

    def get_eth_payload(self):
        return self.payload[16:]

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
