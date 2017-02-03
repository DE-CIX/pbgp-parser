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

from pbgpp.BGP.Exceptions import BGPMessageFactoryError
from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation


class BGPMessage:
    def __init__(self, payload, length, pcap_information):
        self.payload = payload
        self.length = length
        self.type = None
        self.parsed = False
        self.error = None
        self.pcap_information = pcap_information

    def __str__(self):
        # Return the string identifier of the BGP message
        # Example return: <BGPMessage type=UPDATE length=128>
        message_type_string = BGPTranslation.message_type(self.type)
        message_length_string = self.length
        message_parsed_string = BGPTranslation.boolean(self.parsed)
        message_error_string = BGPTranslation.boolean(self.error)

        # Assemble first part of message
        return_string = "<BGPMessage type="

        # Assemble message type
        if message_type_string is not None:
            return_string += message_type_string
        else:
            return_string += "UNKNOWN"

        # Assemble length
        return_string += " " + "length="

        if message_length_string is not None:
            return_string += str(message_length_string)
        else:
            return_string += "UNKNOWN"

        # Assemble parsed
        return_string += " " + "parsed="

        if message_parsed_string is not None:
            return_string += message_parsed_string
        else:
            return_string += "UNKNOWN"

        # Assemble error
        return_string += " " + "error="

        if message_error_string is not None:
            return_string += message_error_string
        else:
            return_string += "UNKNOWN"

        # Close message
        return_string += ">"

        # Return fully assembled message
        return return_string

    def __eq__(self, other):
        if isinstance(other, BGPMessage):
            # Compare raw payload to equate both objects
            return self.payload == other.payload
        else:
            return NotImplemented

    def __len__(self):
        # Return the message length
        return self.length

    def get_type(self):
        # Return the message type
        return self.type

    def get_length(self):
        # Return the message length
        return self.length

    @staticmethod
    def factory(payload, pcap_information):
        logger = logging.getLogger("pbgpp.BGPMessage.factory")

        # Implement factory pattern for easy message class creation
        # First 2 bytes of BGP header is the message length
        # The byte after message length is the message type
        try:
            bgp_header = struct.unpack("!HB", payload[:3])
        except Exception as e:
            # This could happen on a malformed packet
            logger.debug("Unpacking first 3 bytes of BGP message (length and type) failed.")
            raise BGPMessageFactoryError("given payload has no valid message type.")

        message_length = bgp_header[0]
        message_type = bgp_header[1]

        # Plausibility-check for BGP messages
        if message_length is not (len(payload) + 16):
            logger.warning("The unpacked message length does not equal the real payload length.")
            raise BGPMessageFactoryError("parsed message length does not equal real payload length.")

        if message_type == BGPStatics.MESSAGE_TYPE_UPDATE:
            from pbgpp.BGP.Update.Message import BGPUpdateMessage
            return BGPUpdateMessage(payload[3:], message_length, pcap_information)

        if message_type == BGPStatics.MESSAGE_TYPE_KEEPALIVE:
            from pbgpp.BGP.Keepalive.Message import BGPKeepaliveMessage
            return BGPKeepaliveMessage(payload[3:], message_length, pcap_information)

        if message_type == BGPStatics.MESSAGE_TYPE_OPEN:
            from pbgpp.BGP.Open.Message import BGPOpenMessage
            return BGPOpenMessage(payload[3:], message_length, pcap_information)

        if message_type == BGPStatics.MESSAGE_TYPE_NOTIFICATION:
            from pbgpp.BGP.Notification.Message import BGPNotificationMessage
            return BGPNotificationMessage(payload[3:], message_length, pcap_information)

        if message_type == BGPStatics.MESSAGE_TYPE_ROUTE_REFRESH:
            from pbgpp.BGP.RouteRefresh.Message import BGPRouteRefreshMessage
            return BGPRouteRefreshMessage(payload[3:], message_length, pcap_information)

        # No type match
        logger.warning("Factory could not recognize message type")
        raise BGPMessageFactoryError("given payload has no valid message type.")
