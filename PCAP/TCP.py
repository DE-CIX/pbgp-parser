#
# This file is part of PCAP BGP Parser (pbgpp)
#
# Copyright 2016 DE-CIX Management GmbH
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

from PCAP.Information import PCAPLayer4Information


class PCAPTCP:
    BITMASK_FLAGS = 0xfff

    def __init__(self, payload):
        # Assign variables
        self.payload = payload
        self.ports = None

        self.seq = None
        self.ack = None

        self.header_length = None
        self.flags = None
        self.window_size_value = None
        self.checksum = None
        self.urgent_pointer = None

        # Start parsing
        self.__parse()

    def __parse(self):
        tcp_data = struct.unpack("!HHLL", self.payload[0:12])

        source_port = tcp_data[0]
        destination_port = tcp_data[1]
        self.seq = tcp_data[2]
        self.ack = tcp_data[3]

        self.ports = PCAPLayer4Information(source_port, destination_port)

        length_flags = struct.unpack("!H", self.payload[12:14])[0]
        self.header_length = (length_flags >> 12) * 4
        self.flags = (length_flags & self.BITMASK_FLAGS)

    def get_ports(self):
        return self.ports

    def get_seq(self):
        return self.seq

    def get_ack(self):
        return self.ack

    def get_header_length(self):
        return self.header_length

    def get_flags(self):
        return self.flags

    def get_window_size_value(self):
        return self.window_size_value

    def get_checksum(self):
        return self.checksum

    def get_urgent_pointer(self):
        return self.urgent_pointer

    def get_tcp_payload(self):
        return self.payload[self.header_length:]