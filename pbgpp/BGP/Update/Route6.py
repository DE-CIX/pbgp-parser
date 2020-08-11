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

import socket
import struct
import math

from pbgpp.BGP.Exceptions import BGPRouteInitializeError, BGPRouteConvertionError


class BGPRoute6:
    def __init__(self, prefix, prefix_length):
        # Prefix = e.g. 1337:1337:1337:1337::
        # Length = 64
        # To String: 1337:1337:1337:1337::/64 (CIDR notation)

        # Assign values
        self.prefix = prefix
        self.prefix_length = prefix_length
        self.prefix_length_decimal = None

        # Values that need to be assigned due to parsing
        self.prefix_string = None
        self.prefix_length_string = None

        self._parse()

    @classmethod
    def from_binary(cls, prefix, prefix_length):
        # Create a class instance from bytes
        if isinstance(prefix, bytes) and isinstance(prefix_length, bytes):
            return cls(prefix, prefix_length)
        else:
            raise BGPRouteInitializeError("prefix and prefix_length must be instance of bytes.")

    def __str__(self):
        # Return the prefix string that was created during parsing
        return self.prefix_string

    def __eq__(self, other):
        # Compare two routes by comparing the prefix and its length
        if isinstance(other, BGPRoute6):
            return self.prefix == other.prefix and self.prefix_length == other.prefix_length
        else:
            # This wont work for any other classes. Just for BGPRoute objects.
            return NotImplemented

    def _parse(self):
        # Check the prefix length at first as that length is needed to determine
        # how many bytes we need to parse afterwards
        self.prefix_string = ""

        self.prefix_length_decimal = struct.unpack("!B", self.prefix_length)[0]
        self.prefix_length_string = str(self.prefix_length_decimal)

        byte_len = int(math.ceil(self.prefix_length_decimal / 8))

        if byte_len == 0:
            self.prefix_string += "::"
        else:

            i=0
            while i < byte_len:

                if i+1 < byte_len: # interpet two bytes
                    field = struct.unpack("!H", self.prefix[i:i+2])[0]
                    self.prefix_string += str( hex(field)[2:] ) + ":"
                    i+=1

                else:              # interpret one byte
                    field = struct.unpack("!B", self.prefix[i])[0]
                    if field == 0: # if zero, use the approriate formatting
                        self.prefix_string += "0:"
                    else:
                        self.prefix_string += str( hex(field)[2:] ) + "00:"

                i+=1

            if byte_len == 16:
                self.prefix_string = self.prefix_length_string[:-1]
            else:
                self.prefix_string += ":"

        self.prefix_string += "/" + str(self.prefix_length_string)
            