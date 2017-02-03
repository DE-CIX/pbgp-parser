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

from pbgpp.BGP.Update.Route import BGPRoute
from pbgpp.Output.Filter import BGPFilter
from pbgpp.BGP.Statics import BGPStatics


class CommunityValueFilter(BGPFilter):
    def __init__(self, values=[]):
        BGPFilter.__init__(self, values)

    def apply(self, message):
        try:
            # NEXT_HOP is a path attribute of BGP UPDATE message
            # Therefore we first need to make that we are currently handling an UPDATE message
            if message.type is not BGPStatics.MESSAGE_TYPE_UPDATE:
                # Skip messages that are no UPDATE messages
                return None

            for attribute in message.path_attributes:
                # Skip attributes that are no NEXT_HOP attributes
                if attribute.type is not BGPStatics.UPDATE_ATTRIBUTE_COMMUNITIES:
                    continue

                communities = []

                for community in attribute.communities:
                    communities.append(str(community.value))

                for value in self.values:
                    if value in communities:
                        return message

                    # Negative filtering using ~ character
                    if value[0:1] == "~" and value[1:] not in communities:
                        return message

            # Searched value was not found
            return None
        except Exception as e:
            # On error the filtering was not successful (due to wrong fields, etc.)
            return None
