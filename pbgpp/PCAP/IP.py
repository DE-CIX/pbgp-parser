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
from pbgpp.PCAP.Information import PCAPLayer3Information


class PCAPIP:
    PROTO_TCP = 0x0006
    BITMASK_IP_HEADER_LENGTH = 0xF

    IP6_STATIC_HEADER_LENGTH = 40

    IP6_HEADER_HOP_BY_HOP = 0x0
    IP6_HEADER_ROUTING = 0x2B
    IP6_HEADER_FRAGMENT = 0x2C              #not implemented
    IP6_HEADER_ESP = 0x32                   #not implemented
    IP6_HEADER_AUTH = 0x33                  #used for ipsec
    IP6_HEADER_DESTINATION_OPTIONS = 0x3C   

    IP6_HEADER_EXTENSIONS = [IP6_HEADER_HOP_BY_HOP, IP6_HEADER_ROUTING, IP6_HEADER_FRAGMENT, 
                             IP6_HEADER_ESP, IP6_HEADER_AUTH, IP6_HEADER_DESTINATION_OPTIONS]

    def __init__(self, payload):
        # Assign variables
        self.payload = payload
        self.protocol = None
        self.addresses = None

        self.header_length = None
        self.version = None
        self.total_length = None

        # Start parsing
        self.__parse()

    def __parse(self):
        version_length = struct.unpack("!B", self.payload[:1])[0]

        # IP header length and version is packed into 1 byte (8 bit)
        self.header_length = (version_length & self.BITMASK_IP_HEADER_LENGTH) * 4
        self.version = (version_length >> 4)

        if self.version == PCAPLayer3Information.IP_VERSION_4:
            self.total_length = struct.unpack("!H", self.payload[2:4])[0]
            self.protocol = struct.unpack("!B", self.payload[9:10])[0]

            ip_set = struct.unpack("!BBBBBBBB", self.payload[12:20])
            self.addresses = PCAPLayer3Information(ip_set[0:4], ip_set[4:8], PCAPLayer3Information.IP_VERSION_4)

        if self.version == PCAPLayer3Information.IP_VERSION_6:
            self.flow_label = struct.unpack("!L", self.payload[:4])[0] & 0x000FFFFF

            # Extract sender and receiver address
            ip_set = struct.unpack("!16H", self.payload[8:40])
            self.addresses = PCAPLayer3Information(ip_set[:8], ip_set[8:], PCAPLayer3Information.IP_VERSION_6)

            # IPv6 header length, discard packet if Jumbo Frame (not implemented till now)
            self.header_length = self.IP6_STATIC_HEADER_LENGTH
            self.total_length = struct.unpack("!H", self.payload[4:6])[0] + self.header_length
            if self.total_length == self.header_length: # no jumbo frame support
                raise NotImplementedError('Jumbo Frames are not supported')

            # Check if there are header extensions
            self.protocol = struct.unpack("!B", self.payload[6])[0]
            if self.protocol in self.IP6_HEADER_EXTENSIONS:
                
                if self.protocol == self.IP6_HEADER_FRAGMENT or self.protocol == self.IP6_HEADER_ESP or self.protocol == self.IP6_HEADER_AUTH:
                    raise NotImplementedError('Unsupported IP6 extended header extension')

                self.protocol = struct.unpack("!B", self.payload[self.IP6_STATIC_HEADER_LENGTH])
                self.header_length +=struct.unpack("!B", self.payload[self.IP6_STATIC_HEADER_LENGTH + 1]) + 1
                        
            #--HOP LIMIT--  We dont care about that since its not important for the parser

    def get_protocol(self):
        return self.protocol

    def get_addresses(self):
        return self.addresses

    def get_ip_payload(self):
        return self.payload[self.header_length:self.total_length]
