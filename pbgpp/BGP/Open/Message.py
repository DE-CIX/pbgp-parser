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

from pbgpp.BGP.Exceptions import BGPOptionalParameterFactoryError
from pbgpp.BGP.Message import BGPMessage
from pbgpp.BGP.Open.OptionalParameter import BGPOptionalParameter
from pbgpp.BGP.Statics import BGPStatics


class BGPOpenMessage(BGPMessage):
    def __init__(self, payload, length, pcap_information):
        BGPMessage.__init__(self, payload, length, pcap_information)
        self.type = BGPStatics.MESSAGE_TYPE_OPEN
        self.optional_parameter = []
        self.__parse()

    def __parse(self):
        self.parsed = True
        logger = logging.getLogger('pbgpp.BGPOpenMessage.__parse')

        try:
            fields = struct.unpack("!BHHLB", self.payload[:10])
            self.version = fields[0]
            self.asn = fields[1]
            self.hold_time = fields[2]
            self.identifier = fields[3]
            self.optional_parameter_length = fields[4]

            # Parse optional parameters if there are any
            if self.optional_parameter_length > 0:

                # First of all check if the message is malformed
                # The optional parameter length should equal the length of the remaining payload
                if self.optional_parameter_length == len(self.payload[10:]):
                    current_byte_position = 10  # Starting at 10 bytes
                    continue_loop = True

                    while continue_loop:
                        parameter_fields = struct.unpack("!BB", self.payload[current_byte_position:current_byte_position + 2])
                        parameter_type = parameter_fields[0]
                        parameter_length = parameter_fields[1]

                        parameter_payload_start = current_byte_position + 2  # Skip 2 additional bytes for the parameter type and length that were assigned beforehand
                        parameter_payload_stop = parameter_payload_start + parameter_length  # The payload of the optional parameter ends at (payload start marker + length of parameter)

                        # Now building the optional parameter factory
                        self.optional_parameter.append(BGPOptionalParameter.factory(parameter_type, self.payload[parameter_payload_start:parameter_payload_stop]))

                        # If adding was successful we want to continue the loop if there are more parameters left
                        # Therefore we need to adjust the current_byte_position
                        current_byte_position += (2 + parameter_length)  # New byte_position is (old position + (2 bytes header information + parameter length))

                        # If the current byte position minus 10 bytes offset from before is >= optional parameter length
                        if (current_byte_position - 10) >= self.optional_parameter_length:
                            continue_loop = False

                    # Parsing was successful
                    self.error = False

                else:
                    # Optional parameter length does NOT equal the length of the remaining payload - malformed message
                    logger.warning("Optional parameter length does not equal the length of remaining payload.")
                    self.error = True
            else:
                # Parsing was successful
                self.error = False

        except BGPOptionalParameterFactoryError as f:
            # Factory was not able to recognize parameter type - malformed message
            logger.warning("BGPOptionalParameterFactory was not able to recognize parameter type. Exception could be raised due to a malformed message.")
            self.error = True

        except Exception as e:
            # Other strange things could happen
            logger.warning("Unspecified error during packet parsing. Exception could be raised due to a malformed message.")
