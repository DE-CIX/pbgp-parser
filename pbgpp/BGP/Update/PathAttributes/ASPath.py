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
from pbgpp.BGP.Update.ASPathSegment import BGPUpdateASPathSegment
from pbgpp.BGP.Update.PathAttribute import BGPPathAttribute


class PathAttributeASPath(BGPPathAttribute):
    def __init__(self, payload):
        BGPPathAttribute.__init__(self, payload)
        self.type = BGPStatics.UPDATE_ATTRIBUTE_AS_PATH

        # Path attribute specific variables
        self.asn_byte_length = None
        self.path_segments = []

        self.__parse()

    def __str__(self):
        # Display AS_SEQUENCE in brackets (it's an ordered list of ASN)
        # Display AS_SET as raw numbers
        return_string = ""
        first = True

        for segment in self.path_segments:
            if first:
                first = False
                return_string += str(segment)
                continue

            return_string += " " + str(segment)

        return "" if len(return_string) == 0 else return_string

    def __parse(self):
        try:
            self.parsed = True
            self.error = False

            if len(self.payload) > 0:
                self.asn_byte_length = PathAttributeASPath.as_heuristic(self.payload)

                # Handle payload if ASNs are 4 bytes long
                if self.asn_byte_length == 4:
                    continue_loop = True
                    current_byte_position = 0

                    while continue_loop:
                        fields = struct.unpack("!BB", self.payload[current_byte_position:current_byte_position + 2])
                        segment_type = fields[0]
                        segment_length = fields[1]

                        segment_fields = struct.unpack("!" + ("I" * segment_length), self.payload[current_byte_position + 2:current_byte_position + 2 + (segment_length * 4)])

                        self.path_segments.append(BGPUpdateASPathSegment.factory(segment_type, segment_fields))

                        current_byte_position += 2 + (segment_length * 4)
                        if current_byte_position >= len(self.payload):
                            continue_loop = False

                # Handle payload if ASNs are 2 bytes long
                elif self.asn_byte_length == 2:
                    continue_loop = True
                    current_byte_position = 0

                    while continue_loop:
                        fields = struct.unpack("!BB", self.payload[current_byte_position:current_byte_position + 2])
                        segment_type = fields[0]
                        segment_length = fields[1]

                        segment_fields = struct.unpack("!" + ("H" * segment_length), self.payload[current_byte_position + 2:current_byte_position + 2 + (segment_length * 2)])

                        self.path_segments.append(BGPUpdateASPathSegment.factory(segment_type, segment_fields))

                        current_byte_position += 2 + (segment_length * 2)
                        if current_byte_position >= len(self.payload):
                            continue_loop = False

                else:
                    # Could not determine the correct byte length of ASN
                    # This SHOULD never happen, but there is no safe way to determine the length
                    self.error = True

            else:
                # There is nothing to parse due to empty payload
                pass

        except Exception as e:
            self.error = True

    def json(self):
        r = {
            "asn_byte_length": self.asn_byte_length,
            "type": self.type,
            "type_string": BGPTranslation.path_attribute(self.type),
            "path_segments": [],
            "error": self.error,
        }

        for segment in self.path_segments:
            r["path_segments"].append(segment.json())

        return r

    @staticmethod
    def as_heuristic(payload):
        # This function is kind of complicated
        # Problem: There is no clear way to determine if an ASN has two or four bytes length
        # This code is translated from C into Python from Wireshark project
        # @todo Documentation of ASN heuristic code
        current_byte_position = 1

        length = struct.unpack("!B", payload[current_byte_position:current_byte_position + 1])[0]
        current_byte_position += 1

        offset_check = current_byte_position + (2 * length)

        try:
            next_type = struct.unpack("!B", payload[offset_check:offset_check + 1])[0]
        except Exception as e:
            # There is no next type
            next_type = -1

        if offset_check == len(payload):
            assumed_as_length = 2
        elif (next_type == 1) or (next_type == 2) or (next_type == 3) or (next_type == 4):
            j = 0
            asn_is_null = 0
            while (j < length) and (asn_is_null == 0):
                try:
                    check_value = \
                    struct.unpack("!H", payload[current_byte_position + (2 * j):(current_byte_position + (2 * j) + 2)])[0]
                    if check_value == 0:
                        asn_is_null = 1
                except:
                    break
                finally:
                    j += 1

            if asn_is_null == 0:
                assumed_as_length = 2
            else:
                assumed_as_length = 4
        else:
            assumed_as_length = 4

        k = 0
        while k < len(payload):
            k += 1
            length = struct.unpack("!B", payload[k:k + 1])[0]
            k += 1
            k += length * assumed_as_length

        if k == len(payload):
            return assumed_as_length
        else:
            return -1
