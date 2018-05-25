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

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation
from pbgpp.BGP.Update.PathAttribute import BGPPathAttribute
from pbgpp.BGP.Update.Route import BGPRoute


class PathAttributeNextHop(BGPPathAttribute):
    def __init__(self, payload):
        BGPPathAttribute.__init__(self, payload)
        self.type = BGPStatics.UPDATE_ATTRIBUTE_NEXT_HOP

        # Path attribute specific variable
        self.next_hop = None

        self.__parse()

    def __parse(self):
        try:
            self.parsed = True
            self.error = False

            fields = struct.unpack("!I", self.payload)
            self.next_hop = fields[0]

        except Exception as e:
            self.error = True

    def __str__(self):
        if self.parsed and not self.error:
            return str(BGPRoute.decimal_ip_to_string(self.next_hop))
        else:
            return None

    def json(self):
        return {
            "type": self.type,
            "type_string": BGPTranslation.path_attribute(self.type),
            "error": self.error,
            "next_hop": str(BGPRoute.decimal_ip_to_string(self.next_hop))
        }
