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


class BGPUpdateExtendedCommunity:
    def __init__(self, type, sub_type, global_administrator, local_administrator):
        self.type = type
        self.sub_type = sub_type
        self.global_administrator = global_administrator
        self.local_administrator = local_administrator

    def __str__(self):
        if isinstance(self.global_administrator, int) and isinstance(self.local_administrator, int) and isinstance(self.type, int) and isinstance(self.sub_type, int):
            type = self.type
            sub_type = self.sub_type
            global_administrator = self.global_administrator
            local_administrator = self.local_administrator

        elif isinstance(self.global_administrator, bytes) and isinstance(self.local_administrator, bytes) and isinstance(self.type, bytes) and isinstance(self.sub_type, bytes):
            type = struct.unpack("!B", self.type)[0]
            sub_type = struct.unpack("!B", self.sub_type)[0]
            global_administrator = struct.unpack("!H", self.global_administrator)[0]
            local_administrator = struct.unpack("!I", self.local_administrator)[0]

        else:
            return ""

        type_string = BGPTranslation.extended_community(type, sub_type)

        return type_string + " (" + str(self.global_administrator) + ":" + str(self.local_administrator) + ")"

    def json(self):
        r = {
            "type": self.type,
            "type_string": BGPTranslation.extended_community_type(self.type),
            "sub_type": self.sub_type,
            "sub_type_string": BGPTranslation.extended_community_subtype(self.type, self.sub_type),
            "global_administrator": self.global_administrator,
            "local_administrator": self.local_administrator
        }

        return r
