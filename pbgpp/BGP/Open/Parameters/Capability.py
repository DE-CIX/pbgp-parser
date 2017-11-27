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

from pbgpp.BGP.Open.OptionalParameter import BGPOptionalParameter
from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation


class BGPOptionalParameterCapability(BGPOptionalParameter):

    def __init__(self, payload):
        BGPOptionalParameter.__init__(self, payload)
        self.type = BGPStatics.OPEN_CAPABILITY
        self.capability_list = []
        self.__parse()

    def __parse(self):
        logger = logging.getLogger("pbgpp.BGPOptionalParameterCapability.__parse")

        self.parsed = True

        try:
            current_byte_position = 0
            continue_loop = True

            while continue_loop:
                capability_fields = struct.unpack("!BB", self.payload[current_byte_position:current_byte_position + 2])
                capability_type = capability_fields[0]
                capability_length = capability_fields[1]

                payload_start_marker = current_byte_position + 2
                payload_stop_marker = payload_start_marker + capability_length

                # Use factory pattern to determine the capability class type
                self.capability_list.append(BGPCapability.factory(capability_type, self.payload[payload_start_marker:payload_stop_marker]))

                current_byte_position += (2 + capability_length)
                if current_byte_position >= len(self.payload):
                    continue_loop = False

        except Exception as e:
            logger.warning("Unspecified error during packet parsing. Exception could be raised due to a malformed message.")
            self.error = True

    def json(self):
        capabilities = []

        for c in self.capability_list:
            capabilities.append(c.json())

        return {
            "type": self.type,
            "type_string": BGPTranslation.open_parameter(self.type),
            "capabilities": capabilities
        }


class BGPCapability:

    def __init__(self, payload):
        self.payload = payload
        self.type = None
        self.parsed = False
        self.error = None

    @staticmethod
    def factory(capability_type, payload):
        # Factory pattern for capabilities of capability parameter of OPEN messages
        if capability_type == BGPStatics.CAPABILITY_MULTIPROTOCOL_EXTENSIONS:
            from pbgpp.BGP.Open.Parameters.Capabilities.MultiprotocolExtensions import CapabilityMultiprotocolExtensions
            return CapabilityMultiprotocolExtensions(payload)

        if capability_type == BGPStatics.CAPABILITY_ROUTE_REFRESH:
            from pbgpp.BGP.Open.Parameters.Capabilities.RouteRefresh import CapabilityRouteRefresh
            return CapabilityRouteRefresh(payload)

        if capability_type == BGPStatics.CAPABILITY_ALTERNATIVE_ROUTE_REFRESH:
            from pbgpp.BGP.Open.Parameters.Capabilities.RouteRefresh import CapabilityRouteRefresh
            return CapabilityRouteRefresh(payload, legacy=True)

        if capability_type == BGPStatics.CAPABILITY_OUTBOUND_ROUTE_FILTERING:
            from pbgpp.BGP.Open.Parameters.Capabilities.OutboundRouteFiltering import CapabilityOutboundRouteFilter
            return CapabilityOutboundRouteFilter(payload)

        if capability_type == BGPStatics.CAPABILITY_MULTIPLE_ROUTES_TO_DESTINATION:
            from pbgpp.BGP.Open.Parameters.Capabilities.MultipleRoutesToDestination import CapabilityMultipleRoutesToDestination
            return CapabilityMultipleRoutesToDestination(payload)

        if capability_type == BGPStatics.CAPABILITY_EXTENDED_NEXT_HOP_ENCODING:
            from pbgpp.BGP.Open.Parameters.Capabilities.ExtendedNextHopEncoding import CapabilityExtendedNextHopEncoding
            return CapabilityExtendedNextHopEncoding(payload)

        if capability_type == BGPStatics.CAPABILITY_BGP_EXTENDED:
            from pbgpp.BGP.Open.Parameters.Capabilities.BGPExtended import CapabilityBGPExtended
            return CapabilityBGPExtended(payload)

        if capability_type == BGPStatics.CAPABILITY_GRACEFUL_RESTART:
            from pbgpp.BGP.Open.Parameters.Capabilities.GracefulRestart import CapabilityGracefulRestart
            return CapabilityGracefulRestart(payload)

        if capability_type == BGPStatics.CAPABILITY_SUPPORT_FOR_FOUR_OCTET_AS:
            from pbgpp.BGP.Open.Parameters.Capabilities.SupportForFourOctetAS import CapabilitySupportForFourOctetAS
            return CapabilitySupportForFourOctetAS(payload)

        if capability_type == BGPStatics.CAPABILITY_SUPPORT_FOR_DYNAMIC_CAPABILITY:
            from pbgpp.BGP.Open.Parameters.Capabilities.SupportForDynamicCapability import CapabilitySupportForDynamicCapability
            return CapabilitySupportForDynamicCapability(payload)

        if capability_type == BGPStatics.CAPABILITY_MULTISESSION_BGP:
            from pbgpp.BGP.Open.Parameters.Capabilities.MultisessionBGP import CapabilityMultisessionBGP
            return CapabilityMultisessionBGP(payload)

        if capability_type == BGPStatics.CAPABILITY_ADD_PATH:
            from pbgpp.BGP.Open.Parameters.Capabilities.AddPath import CapabilityAddPath
            return CapabilityAddPath(payload)

        if capability_type == BGPStatics.CAPABILITY_ENHANCED_ROUTE_REFRESH:
            from pbgpp.BGP.Open.Parameters.Capabilities.EnhancedRouteRefresh import CapabilityEnhancedRouteRefresh
            return CapabilityEnhancedRouteRefresh(payload)

        if capability_type == BGPStatics.CAPABILITY_LONG_LIVED_GRACEFUL_RESTART:
            from pbgpp.BGP.Open.Parameters.Capabilities.LongLivedGracefulRestart import CapabilityLongLivedGracefulRestart
            return CapabilityLongLivedGracefulRestart(payload)

        if capability_type == BGPStatics.CAPABILITY_FQDN:
            from pbgpp.BGP.Open.Parameters.Capabilities.FQDN import CapabilityFQDN
            return CapabilityFQDN(payload)

        # No type match
        from pbgpp.BGP.Open.Parameters.Capabilities.Unknown import CapabilityUnknown
        return CapabilityUnknown(payload, unknown_type=capability_type)
