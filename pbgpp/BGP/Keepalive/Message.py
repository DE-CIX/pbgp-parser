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

from pbgpp.BGP.Message import BGPMessage
from pbgpp.BGP.Statics import BGPStatics


class BGPKeepaliveMessage(BGPMessage):
    def __init__(self, payload, length, pcap_information):
        BGPMessage.__init__(self, payload, length, pcap_information)
        self.type = BGPStatics.MESSAGE_TYPE_KEEPALIVE
        self.__parse()

    def __parse(self):
        logger = logging.getLogger("pbgpp.BGPKeepaliveMessage.__parse")

        # Check for message length as this is the only possible check we can run on KEEPALIVE messages
        if self.length is not BGPStatics.KEEPALIVE_FIXED_LENGTH:
            logger.warning("KEEPALIVE message is " + str(self.length) + " bytes long, but mandatory length of KEEPALIVE messages is " + str(BGPStatics.KEEPALIVE_FIXED_LENGTH) + " bytes.")
            self.error = True
        else:
            self.error = False

        # Set parsed to TRUE in any case!
        self.parsed = True
