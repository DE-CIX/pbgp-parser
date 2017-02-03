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


class PathAttributeOrigin(BGPPathAttribute):
    def __init__(self, payload):
        BGPPathAttribute.__init__(self, payload)
        self.type = BGPStatics.UPDATE_ATTRIBUTE_ORIGIN

        self.origin_value = None

        self.__parse()

    def __parse(self):
        try:
            self.origin_value = struct.unpack("!B", self.payload[0:1])[0]

            self.error = False
            self.parsed = True
        except Exception as e:
            self.error = True

    def __str__(self):
        return BGPTranslation.origin(self.origin_value)

    def json(self):
        return {
            "origin": self.origin_value,
            "origin_string": BGPTranslation.origin(self.origin_value),
            "type": self.type,
            "type_string": BGPTranslation.path_attribute(self.type),
            "error": self.error,
        }