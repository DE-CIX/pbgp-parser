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

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation

from pbgpp.BGP.Update.Route import BGPRoute
from pbgpp.BGP.Update.PathAttribute import BGPPathAttribute
from pbgpp.BGP.Update.PathAttributes.MPNextHop import MPNextHop

import struct
import socket
import math

class PathAttributeMPUnReachNLRI(BGPPathAttribute):
    """
    RFC 4760

        +---------------------------------------------------------+
        | Address Family Identifier (2 octets)                    |
        +---------------------------------------------------------+
        | Subsequent Address Family Identifier (1 octet)          |
        +---------------------------------------------------------+
        | Withdrawn Routes (variable)                             |
        +---------------------------------------------------------+
    """

    def __init__(self, payload):
        BGPPathAttribute.__init__(self, payload)
        self.type = BGPStatics.UPDATE_ATTRIBUTE_MP_UNREACH_NLRI
        
        self.afi = 0
        self.safi = 0

        self.nlri = []
        
        self.__parse()

    def __parse(self):
        self.parsed = True
        self.error = False 
        payload_pointer = 0

        self.afi = struct.unpack("!H", self.payload[:2])[0]
        self.safi = struct.unpack("!B", self.payload[2])[0]
       
        payload_pointer = 3

        try:
            if self.afi == 1: #IPv4
                while payload_pointer < len(self.payload):
                    prefix_len = struct.unpack("!B", self.payload[payload_pointer])[0]
                    prefix_len_bytes = int(math.ceil(prefix_len / 8.0))
                    
                    self.nlri.append(BGPRoute.from_binary(self.payload[payload_pointer+1:payload_pointer+1+prefix_len_bytes], self.payload[payload_pointer]))

                    payload_pointer += prefix_len_bytes + 1
                    
            elif self.afi == 2: #IPv6
                while payload_pointer < len(self.payload):
                    prefix_len = struct.unpack("!B", self.payload[payload_pointer])[0]
                    prefix_len_bytes = int(math.ceil(prefix_len / 8.0))
                    
                    self.nlri.append(BGPRoute.from_binary(self.payload[payload_pointer+1:payload_pointer+1+prefix_len_bytes], self.payload[payload_pointer], BGPStatics.IP6_CODE))

                    payload_pointer += prefix_len_bytes + 1
                
            else:
                raise NotImplementedError

        except Exception as e: 
            self.error = True
                
    def __str__(self):
        output = "UNREACH_NLRI: NLRI: ["
        for i in self.nlri:
            output += str(i) + ", "
        output = output[:-2] + "]"
        return output

    def json(self): #overload of parentclass function
        json= {
            "afi": self.afi,
            "safi": self.safi,

            "unreach_nlri": [],
        }

        for nlri in self.nlri:
            json["unreach_nlri"].append(str(nlri))
        
        return json
