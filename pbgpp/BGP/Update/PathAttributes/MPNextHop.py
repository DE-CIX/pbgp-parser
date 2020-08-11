#
# This file is part of PCAP BGP Parser (pbgpp)
#
# Copyright 2016-2020 DE-CIX Management GmbH
# Author: Christopher Moeller <christopher.moeller@de-cix.net>
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

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Update.Route import BGPRoute

import struct
import socket

class MPNextHop:
    "This class is an extension of the MP_REACH field"
    def __init__(self, payload, proto):
        self.payload = payload
        self.proto = proto

        self.next_hop = None #string representation of address

        self.__parse()

    def __parse(self):
        try:
            self.parsed = True
            self.error = False

            if self.proto == socket.AF_INET:
                fields = struct.unpack("!4B", self.payload)
                self.next_hop = str(fields[0]) + "." + str(fields[1]) + "." + str(fields[2]) + "." + str(fields[3])

            else:
                fields = struct.unpack("!8H", self.payload)
                next_hop = ""
                for i in fields:
                    next_hop += str( hex(i)[2:] ) + ":" 
                self.next_hop = next_hop[:-1]

        except Exception as e:
            self.error = True

    def __str__(self):
        if self.parsed and not self.error:
            return self.next_hop
        else:
            return None

