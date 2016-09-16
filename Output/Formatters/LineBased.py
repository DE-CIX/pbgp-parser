#
# This file is part of PCAP BGP Parser (pbgpp)
#
# Copyright 2016 DE-CIX Management GmbH
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

from BGP.Statics import BGPStatics
from BGP.Translation import BGPTranslation
from BGP.Update.PathAttributes.ASPath import PathAttributeASPath
from BGP.Update.PathAttributes.Communities import PathAttributeCommunities
from BGP.Update.PathAttributes.NextHop import PathAttributeNextHop
from BGP.Update.PathAttributes.Origin import PathAttributeOrigin
from Output.Formatter import BGPFormatter


class LineBasedFormatter(BGPFormatter):
    FIELD_MESSAGE_TIMESTAMP = "message.timestamp"
    FIELD_MESSAGE_IP_SOURCE = "message.ip.source"
    FIELD_MESSAGE_IP_DESTINATION = "message.ip.destination"
    FIELD_MESSAGE_MAC_SOURCE = "message.mac.source"
    FIELD_MESSAGE_MAC_DESTINATION = "message.mac.destination"
    FIELD_MESSAGE_LENGTH = "message.length"
    FIELD_MESSAGE_TYPE = "message.type"

    FIELD_UPDATE_SUBTYPE = "update.subtype"
    FIELD_UPDATE_PATH_ATTRIBUTES_LENGTH = "update.path_attributes_length"
    FIELD_UPDATE_WITHDRAWN_ROUTES_LENGTH = "update.withdrawn_routes_length"
    FIELD_UPDATE_WITHDRAWN_ROUTES = "update.withdrawn_routes"
    FIELD_UPDATE_NLRI = "update.nlri"
    FIELD_UPDATE_ATTRIBUTE_ORIGIN = "update.attribute.origin"
    FIELD_UPDATE_ATTRIBUTE_AS_PATH = "update.attribute.as_path"
    FIELD_UPDATE_ATTRIBUTE_AS_PATH_LAST_ASN = "update.attribute.as_path.last_asn"
    FIELD_UPDATE_ATTRIBUTE_NEXT_HOP = "update.attribute.next_hop"
    FIELD_UPDATE_ATTRIBUTE_COMMUNITIES = "update.attribute.communities"
    FIELD_UPDATE_ATTRIBUTE_EXTENDED_COMMUNITIES = "update.attribute.extended_communities"

    REGISTERED_FIELDS = [FIELD_MESSAGE_TIMESTAMP,
                         FIELD_MESSAGE_IP_SOURCE,
                         FIELD_MESSAGE_IP_DESTINATION,
                         FIELD_MESSAGE_MAC_SOURCE,
                         FIELD_MESSAGE_MAC_DESTINATION,
                         FIELD_MESSAGE_LENGTH,
                         FIELD_MESSAGE_TYPE,
                         FIELD_UPDATE_SUBTYPE,
                         FIELD_UPDATE_PATH_ATTRIBUTES_LENGTH,
                         FIELD_UPDATE_WITHDRAWN_ROUTES_LENGTH,
                         FIELD_UPDATE_WITHDRAWN_ROUTES,
                         FIELD_UPDATE_NLRI,
                         FIELD_UPDATE_ATTRIBUTE_ORIGIN,
                         FIELD_UPDATE_ATTRIBUTE_AS_PATH,
                         FIELD_UPDATE_ATTRIBUTE_AS_PATH_LAST_ASN,
                         FIELD_UPDATE_ATTRIBUTE_NEXT_HOP,
                         FIELD_UPDATE_ATTRIBUTE_COMMUNITIES,
                         FIELD_UPDATE_ATTRIBUTE_EXTENDED_COMMUNITIES]

    def __init__(self, fields=None, separator="\t"):
        if not fields:
            self.fields = ["message.timestamp", "message.type", "message.ip.source", "message.ip.destination"]
        else:
            self.fields = None

        self.separator = separator

    def apply(self, message):
        r = ""

        for f in self.fields:
            if f == self.FIELD_MESSAGE_TIMESTAMP:
                r += self.separator + str(message.pcap_information.get_timestamp()[0]) + "." + str(message.pcap_information.get_timestamp()[1])
            elif f == self.FIELD_MESSAGE_IP_SOURCE:
                r += self.separator + message.pcap_information.get_ip().get_source_string()
            elif f == self.FIELD_MESSAGE_IP_DESTINATION:
                r += self.separator + message.pcap_information.get_ip().get_destination_string()
            elif f == self.FIELD_MESSAGE_MAC_SOURCE:
                r += self.separator + message.pcap_information.get_mac().get_source_string()
            elif f == self.FIELD_MESSAGE_MAC_DESTINATION:
                r += self.separator + message.pcap_information.get_mac().get_destination_string()
            elif f == self.FIELD_MESSAGE_LENGTH:
                r += self.separator + str(message.length)
            elif f == self.FIELD_MESSAGE_TYPE:
                r += self.separator + BGPTranslation.message_type(message.type)
            elif f == self.FIELD_UPDATE_SUBTYPE:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    r += self.separator + BGPTranslation.update_subtype(message.subtype)
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_PATH_ATTRIBUTES_LENGTH:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    r += self.separator + str(message.path_attributes_length)
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_WITHDRAWN_ROUTES_LENGTH:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    r += self.separator + str(message.withdrawn_routes_length)
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_WITHDRAWN_ROUTES:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    if len(message.withdrawn_routes) > 0:
                        add = ""

                        for route in message.withdrawn_routes:
                            add += ";" + str(route)

                        # Skip first separator character
                        r += self.separator + add[1:]
                    else:
                        r += self.separator
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_NLRI:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    if len(message.nlri) > 0:
                        add = ""

                        for route in message.nlri:
                            add += ";" + str(route)

                        # Skip first separator character
                        r += self.separator + add[1:]
                    else:
                        r += self.separator
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_ATTRIBUTE_ORIGIN:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    if len(message.path_attributes) > 0:
                        for attribute in message.path_attributes:
                            # We found the correct path attribute
                            if isinstance(attribute, PathAttributeOrigin):
                                r += self.separator + str(attribute)
                                break
                    else:
                        r += self.separator
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_ATTRIBUTE_AS_PATH:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    if len(message.path_attributes) > 0:
                        for attribute in message.path_attributes:
                            # We found the correct path attribute
                            if isinstance(attribute, PathAttributeASPath):
                                if len(attribute.path_segments) > 0:
                                    add = ""

                                    for segment in attribute.path_segments:
                                        add += ";" + str(segment)

                                    # Skip first separator
                                    r += self.separator + add[1:]
                                    break
                                else:
                                    r += self.separator
                                    break

                    else:
                        r += self.separator
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_ATTRIBUTE_NEXT_HOP:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    if len(message.path_attributes) > 0:
                        for attribute in message.path_attributes:
                            # We found the correct path attribute
                            if isinstance(attribute, PathAttributeNextHop):
                                r += self.separator + str(attribute)
                                break
                    else:
                        r += self.separator
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_ATTRIBUTE_COMMUNITIES:
                # We can only display this information if we are handling an UPDATE message
                if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
                    if len(message.path_attributes) > 0:
                        for attribute in message.path_attributes:
                            # We found the correct path attribute
                            if isinstance(attribute, PathAttributeCommunities):
                                if len(attribute.communities) > 0:
                                    add = ""
                                    for community in attribute.communities:
                                        add += ";" + str(community)

                                    r += self.separator + add[1:]
                                    break
                                else:
                                    r += self.separator
                    else:
                        r += self.separator
                else:
                    r += self.separator
            elif f == self.FIELD_UPDATE_ATTRIBUTE_EXTENDED_COMMUNITIES:
                # @todo Find a good way to display extended communities in just one line
                r += self.separator
            else:
                # No field match
                pass

        # Delete first tab
        return r[1:]