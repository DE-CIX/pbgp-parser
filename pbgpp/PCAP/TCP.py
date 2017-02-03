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

from pbgpp.PCAP.Information import PCAPLayer4Information


class PCAPTCP:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self, payload):
        # Assign variables
        self.payload = payload
        self.ports = None

        self.seq = None
        self.ack = None

        self.flag_fin = False
        self.flag_syn = False
        self.flag_rst = False
        self.flag_psh = False
        self.flag_ack = False
        self.flag_urg = False
        self.flag_ece = False
        self.flag_cwr = False

        self.header_length = None
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

        tcp_flags = struct.unpack("!B", self.payload[13:14])[0]
        if tcp_flags & self.FIN:
            self.flag_fin = True

        if tcp_flags & self.SYN:
            self.flag_syn = True

        if tcp_flags & self.RST:
            self.flag_rst = True

        if tcp_flags & self.PSH:
            self.flag_psh = True

        if tcp_flags & self.ACK:
            self.flag_ack = True

        if tcp_flags & self.URG:
            self.flag_urg = True

        if tcp_flags & self.ECE:
            self.flag_ece = True

        if tcp_flags & self.CWR:
            self.flag_cwr = True

    def get_ports(self):
        return self.ports

    def get_seq(self):
        return self.seq

    def get_ack(self):
        return self.ack

    def get_header_length(self):
        return self.header_length

    def get_window_size_value(self):
        return self.window_size_value

    def get_checksum(self):
        return self.checksum

    def get_urgent_pointer(self):
        return self.urgent_pointer

    def get_tcp_payload(self):
        return self.payload[self.header_length:]
