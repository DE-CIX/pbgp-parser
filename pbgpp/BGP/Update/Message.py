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

import logging
import struct

from pbgpp.BGP.Exceptions import BGPWithdrawnPrefixError, BGPNLRIError, BGPError
from pbgpp.BGP.Message import BGPMessage
from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Update.Flags import BGPUpdateFlags
from pbgpp.BGP.Update.PathAttribute import BGPPathAttribute
from pbgpp.BGP.Update.Route import BGPRoute


class BGPUpdateMessage(BGPMessage):
    def __init__(self, payload, length, pcap_information):
        BGPMessage.__init__(self, payload, length, pcap_information)
        self.type = BGPStatics.MESSAGE_TYPE_UPDATE
        self.subtype = BGPStatics.UPDATE_TYPE_NONE

        # Message specific variables
        self.path_attributes = []
        self.path_attributes_length = None

        self.withdrawn_routes = []
        self.withdrawn_routes_length = None

        self.nlri = []

        self.__parse()

    def __parse(self):
        self.parsed = True

        try:
            # Check last two bytes of byte payload - if they are set to zero we don't have any path attributes
            if struct.unpack("!H", self.payload[-2:])[0] == 0:
                self.path_attributes_length = 0

            # Unpack the length of withdrawn routes field and add 2 bytes to the current byte marker position
            self.withdrawn_routes_length = struct.unpack("!H", self.payload[:2])[0]
            current_byte_position = 2

            # Start parsing withdrawn routes
            if self.withdrawn_routes_length is not 0:
                continue_loop = True

                # Loop through withdrawals
                while continue_loop:
                    # First of all we need to parse the length of the withdrawn prefix. Depending on the prefix length
                    # we can determine the length following prefix itself
                    prefix_length_bytes = self.payload[current_byte_position:current_byte_position + 1]
                    prefix_length = struct.unpack("!B", prefix_length_bytes)[0]
                    current_byte_position += 1

                    if 0 <= prefix_length <= 8:
                        # Length of prefix field: 1 Byte
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 1]
                        current_byte_position += 1

                    elif 9 <= prefix_length <= 16:
                        # Length of prefix field: 2 Bytes
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 2]
                        current_byte_position += 2

                    elif 17 <= prefix_length <= 24:
                        # Length of prefix field: 3 Bytes
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 3]
                        current_byte_position += 3

                    elif 25 <= prefix_length:
                        # Length of prefix field: 4 Bytes
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 4]
                        current_byte_position += 4

                    else:
                        self.error = True
                        raise BGPWithdrawnPrefixError("can't match prefix length.")

                    # Add BGPRoute object with information about the withdrawn route to list
                    self.withdrawn_routes.append(BGPRoute.from_binary(prefix_bytes, prefix_length_bytes))

                    # Check if we are at the end of the payload
                    if self.withdrawn_routes_length <= current_byte_position:
                        # If yes we need to stop the iteration
                        continue_loop = False

            # Second step: Continue with the path attributes
            if self.path_attributes_length is None:
                # First of all get the attributes length field and update the current byte position
                self.path_attributes_length = struct.unpack("!H", self.payload[current_byte_position:current_byte_position + 2])[0]
                current_byte_position += 2

            # Now we have a correct path_attributes_length stored. If this length is zero we don't need to do anything
            if self.path_attributes_length is not 0:
                continue_loop = True

                # Loop through path attributes
                while continue_loop:
                    # Now comes a tricky part of UPDATE message parsing. Each path attribute has a flag bitfield.
                    # One of those flags is called 'extended length'. If it's set to 1 the following attribute fields
                    # are 2 bytes long. But if it's set to zero it's just 1 byte long ...

                    # So first of all: Flag parsing!
                    attribute_flags = BGPUpdateFlags(struct.unpack("!B", self.payload[current_byte_position:current_byte_position + 1])[0])
                    current_byte_position += 1

                    if attribute_flags.length:
                        # We got an extended length flag
                        attribute_fields = struct.unpack("!BH", self.payload[current_byte_position:current_byte_position + 3])
                        current_byte_position += 3
                    else:
                        # We got a normal length flag
                        attribute_fields = struct.unpack("!BB", self.payload[current_byte_position:current_byte_position + 2])
                        current_byte_position += 2

                    # Finally assign the variables
                    attribute_type = attribute_fields[0]
                    attribute_length = attribute_fields[1]

                    # Now we are using the factory pattern again to determine
                    # which kind of attribute we have to add the list
                    self.path_attributes.append(BGPPathAttribute.factory(attribute_type, self.payload[current_byte_position:current_byte_position + attribute_length], attribute_flags))

                    # Add length of attribute to position pointer
                    current_byte_position += attribute_length

                    # Check if there are further path attributes to parse
                    if current_byte_position >= self.path_attributes_length:
                        continue_loop = False

            # Third step: NLRIs
            if len(self.payload) > (self.path_attributes_length + 4 + self.withdrawn_routes_length):

                continue_loop = True

                # The four bytes that get added to the attributes and routes length are the two two-byte fields
                # for path attribute length and withdrawn routes length
                current_byte_position = self.path_attributes_length + 4 + self.withdrawn_routes_length

                while continue_loop:
                    # First of all we have to check the prefix length as byte-length of the following
                    # prefix depends on its prefix length (This is a 1-byte-field)
                    prefix_length_bytes = self.payload[current_byte_position:current_byte_position + 1]
                    prefix_length = struct.unpack("!B", prefix_length_bytes)[0]
                    current_byte_position += 1

                    if 0 <= prefix_length <= 8:
                        # Length of prefix field: 1 Byte
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 1]
                        current_byte_position += 1
                    elif 9 <= prefix_length <= 16:
                        # Length of prefix field: 2 Bytes
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 2]
                        current_byte_position += 2
                    elif 17 <= prefix_length <= 24:
                        # Length of prefix field: 3 Bytes
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 3]
                        current_byte_position += 3
                    elif 25 <= prefix_length:
                        # Length of prefix field: 4 Bytes
                        prefix_bytes = self.payload[current_byte_position:current_byte_position + 4]
                        current_byte_position += 4
                    else:
                        self.error = True
                        raise BGPWithdrawnPrefixError("can't match prefix length.")

                    try:
                        self.nlri.append(BGPRoute.from_binary(prefix_bytes, prefix_length_bytes))
                    except BGPError as e:
                        raise BGPNLRIError("can't append NLRI to message (error: " + str(e) + ")")

                    if current_byte_position >= len(self.payload):
                        continue_loop = False

            # Determine sub-type for filtering
            # Using bit flags for easier assignment
            if len(self.nlri) > 0:
                self.subtype = (self.subtype | BGPStatics.UPDATE_TYPE_ANNOUNCE)

            if len(self.withdrawn_routes) > 0:
                self.subtype = (self.subtype | BGPStatics.UPDATE_TYPE_WITHDRAWAL)

        except BGPWithdrawnPrefixError as p:
            self.error = True
            logging.info(p)
        except Exception as e:
            self.error = True

        self.error = False
