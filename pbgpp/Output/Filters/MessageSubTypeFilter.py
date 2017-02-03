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


class MessageSubTypeFilter(BGPFilter):
    def __init__(self, values=[]):
        BGPFilter.__init__(self, values)

    def apply(self, message):
        try:
            if message.type is not BGPStatics.MESSAGE_TYPE_UPDATE:
                # Skip messages that are no UPDATE messages
                return None

            for value in self.values:
                negated = False

                if value[0:1] == "~":
                    negated = True
                    value = value[1:]

                if value == "WITHDRAWAL":
                    check_value = BGPStatics.UPDATE_TYPE_WITHDRAWAL
                elif value == "ANNOUNCE":
                    check_value = BGPStatics.UPDATE_TYPE_ANNOUNCE
                elif value == "BOTH":
                    check_value = BGPStatics.UPDATE_TYPE_BOTH
                elif value == "NONE":
                    check_value = BGPStatics.UPDATE_TYPE_NONE
                else:
                    return None

                if not negated and message.subtype == check_value:
                    # Match on message type
                    return message

                if negated and message.subtype != check_value:
                    return message

            # Searched value was not found
            return None
        except Exception as e:
            # On error the filtering was not successful (due to wrong fields, etc.)
            return None
