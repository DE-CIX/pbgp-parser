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
from pbgpp.BGP.Translation import BGPTranslation
from pbgpp.BGP.Update.PathAttributes.ASPath import PathAttributeASPath
from pbgpp.BGP.Update.PathAttributes.Communities import PathAttributeCommunities
from pbgpp.BGP.Update.PathAttributes.LargeCommunities import PathAttributeLargeCommunities
from pbgpp.BGP.Update.PathAttributes.NextHop import PathAttributeNextHop
from pbgpp.BGP.Update.PathAttributes.Origin import PathAttributeOrigin
from pbgpp.Output.Formatter import BGPFormatter
from itertools import chain


class LineBasedFormatter(BGPFormatter):
    FIELD_MESSAGE_TIMESTAMP = ["timestamp"]
    FIELD_MESSAGE_IP_SOURCE = ["source_ip", "src_ip"]
    FIELD_MESSAGE_IP_DESTINATION = ["destination_ip", "dst_ip"]
    FIELD_MESSAGE_MAC_SOURCE = ["source_mac", "src_mac", "mac_src", "mac_source"]
    FIELD_MESSAGE_MAC_DESTINATION = ["destination_mac", "dst_mac", "mac_dst", "mac_destination"]
    FIELD_MESSAGE_LENGTH = ["length"]
    FIELD_MESSAGE_TYPE = ["type"]

    FIELD_UPDATE_SUBTYPE = ["subtype"]
    FIELD_UPDATE_PATH_ATTRIBUTES_LENGTH = ["path_attributes_length"]
    FIELD_UPDATE_WITHDRAWN_ROUTES_LENGTH = ["withdrawn_routes_length"]
    FIELD_UPDATE_WITHDRAWN_ROUTES = ["withdrawn_routes", "withdrawn_route", "withdrawals"]
    FIELD_UPDATE_NLRI = ["prefixes", "prefix", "nlri"]
    FIELD_UPDATE_NLRI_LENGTH = ["prefix_length"]
    FIELD_UPDATE_ATTRIBUTE_ORIGIN = ["origin"]
    FIELD_UPDATE_ATTRIBUTE_AS_PATH = ["as_path"]
    FIELD_UPDATE_ATTRIBUTE_AS_PATH_LAST_ASN = ["as_path_last_asn"]
    FIELD_UPDATE_ATTRIBUTE_NEXT_HOP = ["next_hop"]
    FIELD_UPDATE_ATTRIBUTE_COMMUNITIES = ["communities"]
    FIELD_UPDATE_ATTRIBUTE_LARGE_COMMUNITIES = ["large_communities"]

    FIELD_OPEN_MYASN = ["myasn", "my_asn", "asn"]
    FIELD_OPEN_HOLD_TIME = ["hold_time", "holdtime", "holdtimer", "hold_timer"]
    FIELD_OPEN_VERSION = ["version"]
    FIELD_OPEN_BGP_IDENTIFIER = ["bgp_identifier"]

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
                         FIELD_UPDATE_NLRI_LENGTH,
                         FIELD_UPDATE_ATTRIBUTE_ORIGIN,
                         FIELD_UPDATE_ATTRIBUTE_AS_PATH,
                         FIELD_UPDATE_ATTRIBUTE_AS_PATH_LAST_ASN,
                         FIELD_UPDATE_ATTRIBUTE_NEXT_HOP,
                         FIELD_UPDATE_ATTRIBUTE_COMMUNITIES,
                         FIELD_UPDATE_ATTRIBUTE_LARGE_COMMUNITIES,
                         FIELD_OPEN_MYASN,
                         FIELD_OPEN_HOLD_TIME,
                         FIELD_OPEN_VERSION,
                         FIELD_OPEN_BGP_IDENTIFIER]

    def __init__(self, fields=None, separator='\t'):
        if not fields:
            # If the user is not using --fields parameter fallback to default field set
            # Default: timestamp, message_type, message_subtype, prefixes, withdrawn_routes
            self.fields = [self.FIELD_MESSAGE_TIMESTAMP, self.FIELD_MESSAGE_TYPE, self.FIELD_UPDATE_SUBTYPE, self.FIELD_UPDATE_NLRI, self.FIELD_UPDATE_WITHDRAWN_ROUTES]
        else:
            self.fields = fields

        self.separator = separator

    @staticmethod
    def available_fields():
        output = ""

        for field in LineBasedFormatter.REGISTERED_FIELDS:
            output += ", " + field[0]

        return output[2:]

    @staticmethod
    def is_registered(field):
        for f in LineBasedFormatter.REGISTERED_FIELDS:
            for item in f:
                if item == field:
                    return True

        return False

    def get_field_value(self, f, message):
        # Timestamp
        if f in self.FIELD_MESSAGE_TIMESTAMP:
            return str(message.pcap_information.get_timestamp()[0]) + "." + str(message.pcap_information.get_timestamp()[1])

        # Source IP
        if f in self.FIELD_MESSAGE_IP_SOURCE:
            return message.pcap_information.get_ip().get_source_string()

        # Destination IP
        if f in self.FIELD_MESSAGE_IP_DESTINATION:
            return message.pcap_information.get_ip().get_destination_string()

        # Source MAC
        if f in self.FIELD_MESSAGE_MAC_SOURCE:
            return message.pcap_information.get_mac().get_source_string()

        # Destination MAC
        if f in self.FIELD_MESSAGE_MAC_DESTINATION:
            return message.pcap_information.get_mac().get_destination_string()

        # ASN
        if f in self.FIELD_OPEN_MYASN:
            asn = getattr(message, "asn", False)
            if asn:
                return str(asn)
            return None

        # Hold time
        if f in self.FIELD_OPEN_HOLD_TIME:
            hold_time = getattr(message, "hold_time", False)
            if hold_time:
                return str(hold_time)
            return None

        # BGP Version
        if f in self.FIELD_OPEN_VERSION:
            version = getattr(message, "version", False)
            if version:
                return str(version)
            return None

        # BGP Identifier
        if f in self.FIELD_OPEN_BGP_IDENTIFIER:
            bgp_identifier = getattr(message, "identifier", False)
            if bgp_identifier:
                return str(bgp_identifier)
            return None

        # Message length
        if f in self.FIELD_MESSAGE_LENGTH:
            return str(message.length)

        # Path attributes length
        if f in self.FIELD_UPDATE_PATH_ATTRIBUTES_LENGTH:
            path_attributes_length = getattr(message, "path_attributes_length", False)
            if path_attributes_length:
                return str(path_attributes_length)
            return None

        # Withdrawn routes length
        if f in self.FIELD_UPDATE_WITHDRAWN_ROUTES_LENGTH:
            withdrawn_routes_length = getattr(message, "withdrawn_routes_length", False)
            if withdrawn_routes_length:
                return str(withdrawn_routes_length)
            return None

        # Message type
        if f in self.FIELD_MESSAGE_TYPE:
            return BGPTranslation.message_type(message.type)

        # Message sub type
        if f in self.FIELD_UPDATE_SUBTYPE:
            subtype = getattr(message, "subtype", False)
            if subtype:
                return BGPTranslation.update_subtype(subtype)
            return None

        # Withdrawn routes
        if f in self.FIELD_UPDATE_WITHDRAWN_ROUTES:
            w_routes = getattr(message, "withdrawn_routes", False)
            if w_routes:
                return [str(r) for r in w_routes]
            return None

        # NLRI (announced prefixes)
        if f in self.FIELD_UPDATE_NLRI:
            prefixes = getattr(message, "nlri", False)
            if prefixes:
                return [str(r) for r in prefixes]
            return None

        # NLRI length
        if f in self.FIELD_UPDATE_NLRI_LENGTH:
            prefixes = getattr(message, "nlri", False)
            if prefixes:
                return [r.prefix_length_string for r in prefixes]
            return None

        # Attribute: Origin
        if f in self.FIELD_UPDATE_ATTRIBUTE_ORIGIN:
            path_attributes = getattr(message, "path_attributes", False)
            if path_attributes:
                return [str(a) for a in path_attributes if isinstance(a, PathAttributeOrigin)]
            return None

        # Next hop
        if f in self.FIELD_UPDATE_ATTRIBUTE_NEXT_HOP:
            path_attributes = getattr(message, "path_attributes", False)
            if path_attributes:
                return [str(a) for a in path_attributes if isinstance(a, PathAttributeNextHop)]
            return None

        # Communities
        if f in self.FIELD_UPDATE_ATTRIBUTE_COMMUNITIES or f in self.FIELD_UPDATE_ATTRIBUTE_LARGE_COMMUNITIES:
            path_attributes = getattr(message, "path_attributes", False)
            if path_attributes:  # The split is necessary because communities are not returned as a list?
                communities = [str(pa).split(" ") for pa in path_attributes if isinstance(pa, PathAttributeCommunities)]
                return list(chain.from_iterable(communities))  # Flattens the resulting list
            return None

        # AS path (AS Sets remain unhandled?)
        if f in self.FIELD_UPDATE_ATTRIBUTE_AS_PATH:
            path_attributes = getattr(message, "path_attributes", False)
            if path_attributes:  # The split is necessary because segments are not returned as a list?
                segments = [str(seg).split(" ") for seg in path_attributes if isinstance(seg, PathAttributeASPath)]
                return list(chain.from_iterable(segments))  # Flattens the resulting list
            return None

    def apply(self, message):

        # Get the values
        values = [self.get_field_value(f, message) for f in self.fields]

        # Convert and return to a nice output string, assuming list of lists contained in values
        r = ""
        for i in values:
            if not isinstance(i, list):
                r += str(i)
            else:
                r += " ".join(map(str, i))
            r += self.separator
        return r[:-1]

        # # Convert to a nice output string
        # r = ""
        #
        # for f in self.fields:
        #     if f in self.FIELD_MESSAGE_TIMESTAMP:
        #         r += self.separator + str(message.pcap_information.get_timestamp()[0]) + "." + str(message.pcap_information.get_timestamp()[1])
        #     elif f in self.FIELD_OPEN_MYASN:
        #         # We can only display this information if we are handling an OPEN message
        #         if message.type == BGPStatics.MESSAGE_TYPE_OPEN:
        #             r += self.separator + str(message.asn)
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_OPEN_HOLD_TIME:
        #         # We can only display this information if we are handling an OPEN message
        #         if message.type == BGPStatics.MESSAGE_TYPE_OPEN:
        #             r += self.separator + str(message.hold_time)
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_OPEN_VERSION:
        #         # We can only display this information if we are handling an OPEN message
        #         if message.type == BGPStatics.MESSAGE_TYPE_OPEN:
        #             r = self.separator + str(message.version)
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_OPEN_BGP_IDENTIFIER:
        #         # We can only display this information if we are handling an OPEN message
        #         if message.type == BGPStatics.MESSAGE_TYPE_OPEN:
        #             r += self.separator + str(message.identifier)
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_MESSAGE_IP_SOURCE:
        #         r += self.separator + message.pcap_information.get_ip().get_source_string()
        #     elif f in self.FIELD_MESSAGE_IP_DESTINATION:
        #         r += self.separator + message.pcap_information.get_ip().get_destination_string()
        #     elif f in self.FIELD_MESSAGE_MAC_SOURCE:
        #         r += self.separator + message.pcap_information.get_mac().get_source_string()
        #     elif f in self.FIELD_MESSAGE_MAC_DESTINATION:
        #         r += self.separator + message.pcap_information.get_mac().get_destination_string()
        #     elif f in self.FIELD_MESSAGE_LENGTH:
        #         r += self.separator + str(message.length)
        #     elif f in self.FIELD_MESSAGE_TYPE:
        #         r += self.separator + BGPTranslation.message_type(message.type)
        #     elif f in self.FIELD_UPDATE_SUBTYPE:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             r += self.separator + BGPTranslation.update_subtype(message.subtype)
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_UPDATE_PATH_ATTRIBUTES_LENGTH:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             r += self.separator + str(message.path_attributes_length)
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_UPDATE_WITHDRAWN_ROUTES_LENGTH:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             r += self.separator + str(message.withdrawn_routes_length)
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_UPDATE_WITHDRAWN_ROUTES:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             if len(message.withdrawn_routes) > 0:
        #                 add = ""
        #
        #                 for route in message.withdrawn_routes:
        #                     add += ";" + str(route)
        #
        #                 # Skip first separator character
        #                 r += self.separator + add[1:]
        #             else:
        #                 r += self.separator
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_UPDATE_NLRI:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             if len(message.nlri) > 0:
        #                 add = ""
        #
        #                 for route in message.nlri:
        #                     add += ";" + str(route)
        #
        #                 # Skip first separator character
        #                 r += self.separator + add[1:]
        #             else:
        #                 r += self.separator
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_UPDATE_NLRI_LENGTH:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             if len(message.nlri) > 0:
        #                 add = ""
        #
        #                 for route in message.nlri:
        #                     add += ";" + str(route.prefix_length_string)
        #
        #                 # Skip first separator character
        #                 r += self.separator + add[1:]
        #             else:
        #                 r += self.separator
        #         else:
        #             r += self.separator
        #
        #     elif f in self.FIELD_UPDATE_ATTRIBUTE_ORIGIN:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             if len(message.path_attributes) > 0:
        #                 for attribute in message.path_attributes:
        #                     # We found the correct path attribute
        #                     if isinstance(attribute, PathAttributeOrigin):
        #                         r += self.separator + str(attribute)
        #                         break
        #             else:
        #                 r += self.separator
        #         else:
        #             r += self.separator
        #
        #     #elif f in self.FIELD_UPDATE_ATTRIBUTE_AS_PATH:
        #     #    print "Drinne"
        #
        #     elif True:
        #         print "F drin: ",
        #         print f in self.FIELD_UPDATE_ATTRIBUTE_AS_PATH
        #         if f in self.FIELD_UPDATE_ATTRIBUTE_AS_PATH:
        #             # We can only display this information if we are handling an UPDATE message
        #             if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #                 if len(message.path_attributes) > 0:
        #                     for attribute in message.path_attributes:
        #                         # We found the correct path attribute
        #                         if isinstance(attribute, PathAttributeASPath):
        #                             if len(attribute.path_segments) > 0:
        #                                 add = ""
        #
        #                                 for segment in attribute.path_segments:
        #                                     add += ";" + str(segment)
        #
        #                                 # Skip first separator
        #                                 r += self.separator + add[1:]
        #
        #                                 break
        #                             else:
        #                                 r += self.separator
        #                                 break
        #                 else:
        #                     r += self.separator
        #             else:
        #                 r += self.separator
        #
        #     elif f in self.FIELD_UPDATE_ATTRIBUTE_NEXT_HOP:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
        #             if len(message.path_attributes) > 0:
        #                 for attribute in message.path_attributes:
        #                     # We found the correct path attribute
        #                     if isinstance(attribute, PathAttributeNextHop):
        #                         r += self.separator + str(attribute)
        #                         nhf = True
        #                         break
        #             else:
        #                 r += self.separator
        #         else:
        #             r += self.separator
        #
        #     elif f in self.FIELD_UPDATE_ATTRIBUTE_COMMUNITIES or f == self.FIELD_UPDATE_ATTRIBUTE_LARGE_COMMUNITIES:
        #         # We can only display this information if we are handling an UPDATE message
        #         if message.type == BGPStatics.MESSAGE_TYPE_UPDATE and message.subtype == BGPStatics.UPDATE_TYPE_ANNOUNCE:
        #             if len(message.path_attributes) > 0:
        #
        #                 communities = None
        #                 for attribute in message.path_attributes:
        #                     if isinstance(attribute, PathAttributeCommunities):
        #                         communities = attribute.communities
        #                     elif isinstance(attribute, PathAttributeLargeCommunities):
        #                         communities = attribute.large_communities
        #
        #                 if communities:
        #                     if len(communities) > 0:
        #                         add = ""
        #                         for community in communities:
        #                             add += ";" + str(community)
        #
        #                         r += self.separator + add[1:]
        #                         break
        #                     else:
        #                         r += self.separator
        #                 else:
        #                     r += self.separator
        #                     break
        #             else:
        #                 r += self.separator
        #         else:
        #             r += self.separator
        #     elif f in self.FIELD_UPDATE_ATTRIBUTE_EXTENDED_COMMUNITIES:
        #         # @todo Find a good way to display extended communities in just one line
        #         r += self.separator
        #     else:
        #         # No field match
        #         pass
        #
        # print r[1:]
        #
        # return r[1:]
