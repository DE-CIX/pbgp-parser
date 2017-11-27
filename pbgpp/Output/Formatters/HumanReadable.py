#!/usr/bin/python
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
from pbgpp.BGP.Update.Route import BGPRoute
from pbgpp.Output.Exceptions import OutputFormatterError
from pbgpp.Output.Formatter import BGPFormatter


class HumanReadableFormatter(BGPFormatter):
    def __init__(self):
        pass

    def apply(self, message):
        # Example return:
        #
        # [BGPMessage UPDATE] - [123.123.123.123 -> 123.123.123.123]
        # |- IP: 123.123.123.123 -> 123.123.123.123
        # |- MAC: 11:11:11:11:11:11 -> 11:11:11:11:11
        # |- Unix Time: 1412416346.123245123
        # |
        # |- Withdrawn Routes Length: 0
        # |- Total Path Attribute Length: 55
        # |- Path Attributes
        # |--- ORIGIN: IGP
        # |--- AS_PATH: (9498 9430)
        # |--- NEXT_HOP: 80.81.194.250
        # |--- COMMUNITIES: 9498:1 9498:11 9498:91
        # |- NLRI
        # |--- 203.190.42.0/24
        ##

        # Initialize basic return string and PCAP information
        string = "[BGPMessage " + BGPTranslation.message_type(message.type) + "] - " + str(message.length) + " Bytes\n"
        string += self.prefix(0) + "MAC: " + message.pcap_information.get_mac().get_source_string(separated=True) + " -> " + message.pcap_information.get_mac().get_destination_string(separated=True) + "\n"
        string += self.prefix(0) + "IP: " + message.pcap_information.get_ip().get_source_string() + ":" + message.pcap_information.get_ports().get_source_string() + " -> " + message.pcap_information.get_ip().get_destination_string() + ":" + message.pcap_information.get_ports().get_destination_string() + "\n"
        string += self.prefix(0) + "Timestamp: " + message.pcap_information.get_timestmap_utc() + " (" + str(message.pcap_information.get_timestamp()[0]) + "." + str(message.pcap_information.get_timestamp()[1]) + ")\n"

        # Display additional information
        if BGPStatics.MESSAGE_TYPE_KEEPALIVE == message.type:
            pass

        if BGPStatics.MESSAGE_TYPE_OPEN == message.type:
            # --- Divider for PCAP information
            string += self.prefix(-1) + "\n"

            string += self.prefix(0) + "Version: " + str(message.version) + "\n"
            string += self.prefix(0) + "My ASN: " + str(message.asn) + "\n"
            string += self.prefix(0) + "Hold Time: " + str(message.hold_time) + "\n"
            string += self.prefix(0) + "BGP Identifier: " + str(BGPRoute.decimal_ip_to_string(message.identifier)) + "\n"

            # --- Optional Parameters
            string += self.prefix(0) + "Optional Parameters Length: " + str(message.optional_parameter_length) + " Bytes" + "\n"

            # Process optional parameters
            if message.optional_parameter_length > 0:
                string += self.prefix(0) + "Optional Parameters:" + "\n"

                for parameter in message.optional_parameter:
                    if parameter.type == BGPStatics.OPEN_CAPABILITY:
                        string += self.prefix(1) + "Parameter: Capability" + "\n"

                        # Process capabilities
                        for capability in parameter.capability_list:
                            if capability.type is not BGPStatics.CAPABILITY_UNKNOWN:
                                string += self.prefix(2) + BGPTranslation.capability(capability.type) + " (" + str(capability.type) + ")\n"
                            else:
                                string += self.prefix(2) + str(capability) + "\n"

                    elif parameter.type == BGPStatics.OPEN_AUTHENTICATION:
                        string += self.prefix(1) + "Parameter: Authentication" + "\n"
                    elif parameter.type == BGPStatics.OPEN_RESERVED:
                        string += self.prefix(1) + "Parameter: Reserved" + "\n"

        if BGPStatics.MESSAGE_TYPE_UPDATE == message.type:
            # --- Divider for PCAP information
            string += self.prefix(-1) + "\n"

            # --- Update Message Sub-Type
            string += self.prefix(0) + "Update Message Sub-Type: " + BGPTranslation.update_subtype(message.subtype) + "\n"

            # --- Lengths
            string += self.prefix(0) + "Withdrawn Routes Length: " + str(message.withdrawn_routes_length) + " Bytes\n"
            string += self.prefix(0) + "Total Path Attribute Length: " + str(message.path_attributes_length) + " Bytes\n"


            # --- NLRI
            if len(message.nlri) > 0:
                string += self.prefix(0) + "Prefix (NLRI):" + "\n"

                # Process NLRI
                for route in message.nlri:
                    string += self.prefix(1) + str(route) + "\n"

            # --- Path Attributes
            if message.path_attributes_length > 0:

                # Process path attributes
                for attribute in message.path_attributes:
                    string += self.prefix(0) + "Path Attributes:" + "\n"

                    if attribute.type == BGPStatics.UPDATE_ATTRIBUTE_EXTENDED_COMMUNITIES:
                        # Extended Communities must be displayed in another way than other attributes
                        string += self.prefix(1) + BGPTranslation.path_attribute(attribute.type) + ":\n"

                        for community in attribute.extended_communities:
                            string += self.prefix(2) + str(community) + "\n"
                    else:
                        # We got a "normal" path attribute
                        string += self.prefix(1) + BGPTranslation.path_attribute(attribute.type) + ": " + str(attribute) + "\n"

            # --- Withdrawn Routes
            if message.withdrawn_routes_length > 0:
                string += self.prefix(0) + "Withdrawn Routes:" + "\n"

                # Process withdrawn routes
                for route in message.withdrawn_routes:
                    string += self.prefix(1) + str(route) + "\n"

        if BGPStatics.MESSAGE_TYPE_NOTIFICATION == message.type:
            pass

        if BGPStatics.MESSAGE_TYPE_ROUTE_REFRESH == message.type:
            pass

        if BGPStatics.MESSAGE_TYPE_RESERVED == message.type:
            pass

        # Return assembled string plus final line break
        return string + "\n"

    @staticmethod
    def prefix(depth=0):
        if depth < -1:
            raise OutputFormatterError("depth must be bigger than -2.")

        if depth == -1:
            return "|"
        else:
            return "|-" + ("--" * depth) + " "
