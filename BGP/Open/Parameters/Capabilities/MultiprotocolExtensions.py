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

from BGP.Open.Parameters.Capability import BGPCapability
from BGP.Statics import BGPStatics


class CapabilityMultiprotocolExtensions(BGPCapability):
    def __init__(self, payload):
        BGPCapability.__init__(self, payload)
        self.type = BGPStatics.CAPABILITY_MULTIPROTOCOL_EXTENSIONS

        # Capability specific values
        self.afi = None
        self.reserved = None
        self.safi = None

        self.__parse()

    def __parse(self):
        self.parsed = True

        try:
            fields = struct.unpack("!HBB", self.payload)
            # @todo Statics & translation for AFI/SAFI/Reserved field in Multiprotocol Extension capability
            self.afi = fields[0]
            self.reserved = fields[1]
            self.safi = fields[2]

        except Exception as e:
            self.error = True
