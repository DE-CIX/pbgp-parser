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

from binascii import hexlify

import struct

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation
from pbgpp.BGP.Update.ExtendedCommunity import BGPUpdateExtendedCommunity
from pbgpp.BGP.Update.PathAttribute import BGPPathAttribute


class PathAttributeExtendedCommunities(BGPPathAttribute):
    def __init__(self, payload, attribute_flags):
        BGPPathAttribute.__init__(self, payload)
        self.type = BGPStatics.UPDATE_ATTRIBUTE_EXTENDED_COMMUNITIES

        # We need the attribute flags for that path attribute
        self.attribute_flags = attribute_flags
        self.extended_communities = []

        self.__parse()

    def __parse(self):
        try:
            self.parsed = True
            self.error = False

            continue_loop = True
            current_byte_position = 0

            while continue_loop:

                # It's a lot easier and faster when we are checking types and sub-types like this
                fields = struct.unpack("!BBHI", self.payload[current_byte_position:current_byte_position + 8])
                current_byte_position += 8

                try:
                    # One extended community has always 8 bytes payload
                    self.extended_communities.append(BGPUpdateExtendedCommunity(fields[0], fields[1], fields[2], fields[3]))
                except Exception as e:
                    self.error = True

                if current_byte_position >= len(self.payload):
                    continue_loop = False

        except Exception as e:
            self.error = True

    def json(self):
        r = {
            "type": self.type,
            "type_string": BGPTranslation.path_attribute(self.type),
            "error": self.error,
            "extended_communities": []
        }

        for e in self.extended_communities:
            r["extended_communities"].append(e.json())

        return r
