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


class BGPUpdateCommunity:
    def __init__(self, asn, value):
        self.asn = asn
        self.value = value

    def __str__(self):
        if isinstance(self.asn, int) and isinstance(self.value, int):
            return str(self.asn) + ":" + str(self.value)

        elif isinstance(self.asn, bytes) and isinstance(self.value, bytes):
            asn = str(struct.unpack("!H", self.asn)[0])
            value = str(struct.unpack("!H", self.value)[0])

            return asn + ":" + value

        else:
            return None

    def json(self):
        if isinstance(self.asn, int) and isinstance(self.value, int):
            return {
                "asn": self.asn,
                "value": self.value
            }

        elif isinstance(self.asn, bytes) and isinstance(self.value, bytes):
            asn = str(struct.unpack("!H", self.asn)[0])
            value = str(struct.unpack("!H", self.value)[0])

            return {
                "asn": asn,
                "value": value
            }

        else:
            return None
