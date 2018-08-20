#
# This file is part of PCAP BGP Parser (pbgpp)
#
# Copyright 2016-2018 DE-CIX Management GmbH
# Author: Benedikt Rudolph <benedikt.rudolph@de-cix.net>
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

# This filter combines the two alternative ways to signal a blackhole routing
# for a particular  prefix.
#   * The legacy method is to set the next_hop attribute to a special IP address.
#   * The preferred method is to set a well-known BGP Community value (RFC 7999).
# The code for this filter is a combination of CommunityValueFilter and NextHopFilter.
class BlackholeFilter(BGPFilter):
    def __init__(self, values=[]):
        BGPFilter.__init__(self, values)

    def apply(self, message):
        try:
            # NEXT_HOP and COMMUNITIES are attributes of a BGP UPDATE message
            if message.type is not BGPStatics.MESSAGE_TYPE_UPDATE:
                # Skip messages that are no UPDATE messages
                return None

            for attribute in message.path_attributes:
                # Skip attributes that are no NEXT_HOP attributes
                if attribute.type is BGPStatics.UPDATE_ATTRIBUTE_NEXT_HOP:
                    # Here we found the NEXT_HOP attribute - check for blackhole next_hop
                    for value in self.values:
                        if str(BGPRoute.decimal_ip_to_string(attribute.next_hop)) == str(value):
                            # Match on NEXT_HOP attribute - Return message
                            return message

                # Alternatively check if well-known BGP community is set (RFC 7999)
                if attribute.type is BGPStatics.UPDATE_ATTRIBUTE_COMMUNITIES:

                    for community in attribute.communities:
                        if community.asn == 65535 and community.value == 666:
                          return message

            # Searched value was not found
            return None
        except Exception as e:
            # On error the filtering was not successful (due to wrong fields, etc.)
            return None
