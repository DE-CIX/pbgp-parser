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
import re

from pbgpp.BGP.Exceptions import BGPPacketError, BGPPacketHasNoMessagesError, BGPMessageFactoryError, BGPError
from pbgpp.BGP.Message import BGPMessage
from pbgpp.PCAP.Information import PCAPInformation


class BGPPacket:
    def __init__(self, payload, pcap_information):
        # Assign payload and pcap information
        self.payload = payload
        self.pcap_information = pcap_information

        self.message_list = []
        self.__parsed = False
        self.__iteration_position = 0

        # Typecheck pcap information
        if not isinstance(self.pcap_information, PCAPInformation):
            raise BGPPacketError("pcap_information needs to be an object of PCAPInformation class")

        # Parse packet
        self.__parse()

    def __eq__(self, other):
        if isinstance(other, BGPPacket):
            # Compare raw payload to equate both objects
            return self.payload == other.payload
        else:
            return NotImplemented

    def __len__(self):
        # Return the length of raw payload (== the packet length in Bytes)
        return len(self.payload)

    def __iter__(self):
        return self

    def __next__(self):
        try:
            # Return next message
            result = self.message_list[self.__iteration_position]
        except IndexError:
            # No more messages: Raise StopIteration
            raise StopIteration

        # Current iteration position += 1
        self.__iteration_position += 1
        return result

    def __str__(self):
        if self.__parsed:
            # Display amount of BGP messages that are contained in this single TCP packet and their whole length
            return "<BGPPacket messages={0} length={1}>".format(len(self.message_list), len(self.payload))
        else:
            return "<BGPPacket messages=UNKNOWN length=UNKNOWN>"

    def __parse(self):
        logger = logging.getLogger("pbgpp.BGPPacket.__parse")

        # Split the byte string by BGP's magic marker and filter the empty matches from result list
        messages = re.split(b'(?:\xff){16}', self.payload)
        messages = list(filter(None, messages))  # Fastest solution for filtering

        # Check for empty list (in this case we have a malformed/non-BGP packet)
        if len(messages) == 0:
            raise BGPPacketHasNoMessagesError("parsed packet didn't contain any BGP messages")

        # Now iterate through the found messages ...
        for m in messages:
            try:
                # ... and add them to the message list of packet object using a message factory pattern
                self.add_message(BGPMessage.factory(m, self.pcap_information))
            except BGPMessageFactoryError as f:
                # This exception can be raised when no valid message type could be found
                # It's a common exception when there is a malformed packet - therefore: log it as INFO
                logger.info("BGPMessageFactoryError was raised due to unknown message type during initial packet parsing.")
            except BGPPacketError as p:
                # This exception can be raised when system tries to add non-BGPMessage object to message list
                # Uncommon to happen - Better raise an error
                logger.error("Tried to add a non-BGPMessage object to message list.")
            except BGPError as e:
                # A lot of other things could go wrong - fall back to a warning message
                logger.warning("Unspecified BGPError raised during initial packet parsing.")

        self.__parsed = True

    def add_message(self, message):
        try:
            # When trying to add non-BGPMessage object raise new BGPPacketException
            if not isinstance(message, BGPMessage):
                raise BGPPacketError("tried to add non-BGPMessage object to message list")
            else:
                self.message_list.append(message)
                return True
        except Exception as e:
            # There should be no case where this Exception should be raised
            return False

    def remove_message(self, message):
        try:
            # Remove message oject from message list
            if message in self.message_list:
                self.message_list.remove(message)
                return True
            else:
                return False
        except Exception as e:
            # There should be no case where this Exception should be raised
            return False

    def get_pcap_information(self):
        try:
            # Return the stored PCAP information if they have been set, yet
            if self.pcap_information is not None:
                return self.pcap_information
            else:
                return False
        except Exception as e:
            return False

    def get_message_list(self):
        try:
            return self.message_list
        except Exception as e:
            # There should be no case where this Exception should be raised
            return False
