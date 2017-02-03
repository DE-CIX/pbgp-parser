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

import socket
import struct

from pbgpp.BGP.Exceptions import BGPRouteInitializeError, BGPRouteConvertionError


class BGPRoute:
    def __init__(self, prefix, prefix_length):
        # A route is universally used
        # Prefix = e.g. 123.123.123.123
        # Length = 32
        # To String: 123.123.123.123/32 (CIDR notation)

        # Assign values
        self.prefix = prefix
        self.prefix_length = prefix_length

        # Values that need to be assigned due to parsing
        self.prefix_string = None
        self.prefix_length_string = None
        self.prefix_length_decimal = None

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
        if isinstance(other, BGPRoute):
            if self.prefix == other.prefix and self.prefix_length == other.prefix_length:
                return True
        else:
            # This wont work for any other classes. Just for BGPRoute objects.
            return NotImplemented

    def _parse(self):
        # Check the prefix length at first as that length is needed to determine
        # how many bytes we need to parse afterwards
        self.prefix_length_decimal = struct.unpack("!B", self.prefix_length)[0]
        self.prefix_length_string = str(self.prefix_length_decimal)

        if 0 <= self.prefix_length_decimal <= 8:
            # Length of prefix field: 1 Byte
            fields = struct.unpack("!B", self.prefix)
            self.prefix_string = str(fields[0]) + ".0.0.0/" + self.prefix_length_string

        elif 9 <= self.prefix_length_decimal <= 16:
            # Length of prefix field: 2 Bytes
            fields = struct.unpack("!BB", self.prefix)
            self.prefix_string = str(fields[0]) + "." + str(fields[1]) + ".0.0/" + self.prefix_length_string

        elif 17 <= self.prefix_length_decimal <= 24:
            # Length of prefix field: 3 Bytes
            fields = struct.unpack("!BBB", self.prefix)
            self.prefix_string = str(fields[0]) + "." + str(fields[1]) + "." + str(fields[2]) + ".0/" + self.prefix_length_string

        elif 25 <= self.prefix_length_decimal:
            # Length of prefix field: 4 Bytes
            fields = struct.unpack("!BBBB", self.prefix)
            self.prefix_string = str(fields[0]) + "." + str(fields[1]) + "." + str(fields[2]) + "." + str(fields[3]) + "/" + self.prefix_length_string

        else:
            raise BGPRouteConvertionError("was not able to parse bytes.")

    @staticmethod
    def decimal_ip_to_string(decimal):
        return socket.inet_ntoa(struct.pack('!L', decimal))
