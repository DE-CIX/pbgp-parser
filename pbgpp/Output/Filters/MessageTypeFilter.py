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

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.Output.Filter import BGPFilter


class MessageTypeFilter(BGPFilter):
    def __init__(self, values=[]):
        BGPFilter.__init__(self, values)

    def apply(self, message):
        try:
            for value in self.values:
                negated = False

                if value[0:1] == "~":
                    negated = True
                    value = value[1:]

                if value == "RESERVED" or value == "0":
                    check_value = BGPStatics.MESSAGE_TYPE_RESERVED
                elif value == "OPEN" or value == "1":
                    check_value = BGPStatics.MESSAGE_TYPE_OPEN
                elif value == "UPDATE" or value == "2":
                    check_value = BGPStatics.MESSAGE_TYPE_UPDATE
                elif value == "NOTIFICATION" or value == "3":
                    check_value = BGPStatics.MESSAGE_TYPE_NOTIFICATION
                elif value == "KEEPALIVE" or value == "4":
                    check_value = BGPStatics.MESSAGE_TYPE_KEEPALIVE
                elif value == "ROUTE-REFRESH" or value == "ROUTEREFRESH" or value == "5":
                    check_value = BGPStatics.MESSAGE_TYPE_ROUTE_REFRESH
                else:
                    return None

                if not negated and message.type == check_value:
                    # Match on message type
                    return message

                if negated and message.type != check_value:
                    return message

            # Searched value was not found
            return None
        except Exception as e:
            # On error the filtering was not successful (due to wrong fields, etc.)
            return None
