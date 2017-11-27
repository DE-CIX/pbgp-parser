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

from pbgpp.BGP.Statics import BGPStatics


class BGPTranslation:

    @staticmethod
    def boolean(value):
        try:
            if value == True:
                return "True"
            elif value == False:
                return "False"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.boolean")
            logger.warning("Was not able to recognize input value for boolean translation.")

            return "Unknown"

    @staticmethod
    def message_type(value):
        try:
            if value == BGPStatics.MESSAGE_TYPE_RESERVED:
                return "RESERVED"
            elif value == BGPStatics.MESSAGE_TYPE_OPEN:
                return "OPEN"
            elif value == BGPStatics.MESSAGE_TYPE_UPDATE:
                return "UPDATE"
            elif value == BGPStatics.MESSAGE_TYPE_NOTIFICATION:
                return "NOTIFICATION"
            elif value == BGPStatics.MESSAGE_TYPE_KEEPALIVE:
                return "KEEPALIVE"
            elif value == BGPStatics.MESSAGE_TYPE_ROUTE_REFRESH:
                return "ROUTE-REFRESH"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.message_type")
            logger.warning("Was not able to recognize input value for message type translation.")

            return "Unknown"

    @staticmethod
    def update_subtype(value):
        try:
            if value == BGPStatics.UPDATE_TYPE_NONE:
                return "NONE"
            elif value == BGPStatics.UPDATE_TYPE_WITHDRAWAL:
                return "WITHDRAWAL"
            elif value == BGPStatics.UPDATE_TYPE_ANNOUNCE:
                return "ANNOUNCE"
            elif value == BGPStatics.UPDATE_TYPE_BOTH:
                return "ANNOUNCE/WITHDRAWAL"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.update_subtype")
            logger.warning("Was not able to recognize input value for update message subtype translation.")

            return "Unknown"

    @staticmethod
    def open_parameter(value):
        try:
            if value == BGPStatics.OPEN_RESERVED:
                return "RESERVED"
            elif value == BGPStatics.OPEN_AUTHENTICATION:
                return "AUTHENTICATION (Deprecated)"
            elif value == BGPStatics.OPEN_CAPABILITY:
                return "CAPABILITY"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.open_parameter")
            logger.warning("Was not able to recognize input value for open message parameter translation.")

            return "Unknown"

    @staticmethod
    def capability(value):
        try:
            if value == BGPStatics.CAPABILITY_RESERVED:
                return "Reserved"
            elif value == BGPStatics.CAPABILITY_MULTIPROTOCOL_EXTENSIONS:
                return "Multiprotocol extensions capability"
            elif value == BGPStatics.CAPABILITY_ROUTE_REFRESH:
                return "Route refresh capability"
            elif value == BGPStatics.CAPABILITY_OUTBOUND_ROUTE_FILTERING:
                return "Outbound route filtering capability"
            elif value == BGPStatics.CAPABILITY_MULTIPLE_ROUTES_TO_DESTINATION:
                return "Multiple routes to a destination capability"
            elif value == BGPStatics.CAPABILITY_EXTENDED_NEXT_HOP_ENCODING:
                return "Extended next hop encoding capability"
            elif value == BGPStatics.CAPABILITY_BGP_EXTENDED:
                return "BGP-Extended capability (Temporary capability - only valid until 2016-09-30)"
            elif value == BGPStatics.CAPABILITY_GRACEFUL_RESTART:
                return "Graceful restart capability"
            elif value == BGPStatics.CAPABILITY_SUPPORT_FOR_FOUR_OCTET_AS:
                return "Support for 4-octet AS number capability"
            elif value == BGPStatics.CAPABILITY_SUPPORT_FOR_DYNAMIC_CAPABILITY:
                return "Support for dynamic capability (capability specific)"
            elif value == BGPStatics.CAPABILITY_MULTISESSION_BGP:
                return "Multisession BGP capability"
            elif value == BGPStatics.CAPABILITY_ADD_PATH:
                return "ADD-PATH capability"
            elif value == BGPStatics.CAPABILITY_ENHANCED_ROUTE_REFRESH:
                return "Enhanced route refresh capability"
            elif value == BGPStatics.CAPABILITY_LONG_LIVED_GRACEFUL_RESTART:
                return "Long-lived graceful restart (LLGR) capability"
            elif value == BGPStatics.CAPABILITY_FQDN:
                return "FQDN capability"
            elif value == BGPStatics.CAPABILITY_ALTERNATIVE_ROUTE_REFRESH:
                return "Route refresh capability (Cisco-legacy)"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.capability")
            logger.warning("Was not able to recognize input value for capability translation.")

            return "Unknown"

    @staticmethod
    def origin(value):
        try:
            if value == BGPStatics.ORIGIN_IGP:
                return "IGP"
            elif value == BGPStatics.ORIGIN_EGP:
                return "EGP"
            elif value == BGPStatics.ORIGIN_INCOMPLETE:
                return "INCOMPLETE"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.origin")
            logger.warning("Was not able to recognize input value for origin translation.")

            return "Unknown"

    @staticmethod
    def path_attribute(value):
        try:
            if value == BGPStatics.UPDATE_ATTRIBUTE_RESERVED:
                return "Reserved"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_RESERVED_DEVELOPMENT:
                return "Reserved (Development)"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_ORIGIN:
                return "ORIGIN"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_AS_PATH:
                return "AS_PATH"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_NEXT_HOP:
                return "NEXT_HOP"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_MULTI_EXIT_DISC:
                return "MULTI_EXIT_DISC"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_LOCAL_PREF:
                return "LOCAL_PREF"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_ATOMIC_AGGREGATE:
                return "ATOMIC_AGGREGATE"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_AGGREGATOR:
                return "AGGREGATOR"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_COMMUNITIES:
                return "COMMUNITIES"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_ORIGINATOR_ID:
                return "ORIGINATOR_ID"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_CLUSTER_LIST:
                return "CLUSTER_LIST"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_DPA:
                return "DPA"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_ADVERTISER:
                return "ADVERTISER"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_RCID_PATH_CLUSTER_ID:
                return "RCID_PATH / CLUSTER_ID"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_MP_REACH_NLRI:
                return "MP_REACH_NLRI"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_MP_UNREACH_NLRI:
                return "MP_UNREACH_NLRI"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_EXTENDED_COMMUNITIES:
                return "EXTENDED_COMMUNITIES"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_AS4_PATH:
                return "AS4_PATH"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_AS4_AGGREGATOR:
                return "AS4_AGGREGATOR"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_SAFI_SSA:
                return "SAFI Specific Attribute (SSA)"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_CONNECTOR_ATTRIBUTE:
                return "Connector Attribute"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_AS_PATHLIMIT:
                return "AS_PATHLIMIT (deprecated)"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_PMSI_TUNNEL:
                return "PMSI_TUNNEL"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_TUNNEL_ENCAPSULATION:
                return "Tunnel Encapsulation Attribute"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_TRAFFIC_ENGINEERING:
                return "Traffic Engineering"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_IPV6_ADDRESS_SPECIFIC_EXTENDED_COMMUNITY:
                return "IPv6 Address Specific Extended Community"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_AIGP:
                return "AIGP"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_PE_DISTINGUISHER_LABLES:
                return "PE Distinguisher Labels"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_BGP_ENTROPY_LABEL_CAPABILITY:
                return "BGP Entropy Label Capability Attribute"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_BGP_LS:
                return "BGP-LS Attribute"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_ATTR_SET:
                return "ATTR_SET"
            elif value == BGPStatics.UPDATE_ATTRIBUTE_LARGE_COMMUNITIES:
                return "LARGE_COMMUNITIES"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.path_attribute")
            logger.warning("Was not able to recognize input value for path attribute translation.")

            return "Unknown"

    @staticmethod
    def extended_community(type, subtype):
        try:
            type_string = BGPTranslation.extended_community_type(type)

            if type == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_t_two_octet_as_subtype(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_t_ipv4_address_subtype(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_t_four_octet_as_subtype(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_T_OPAQUE:
                sub_type_string = BGPTranslation.extended_community_t_opaque(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_T_QOS_MARKING:
                sub_type_string = ""
            elif type == BGPStatics.EXT_COMMUNITY_T_COS_CAPABILITY:
                sub_type_string = ""
            elif type == BGPStatics.EXT_COMMUNITY_T_EVPN:
                sub_type_string = BGPTranslation.extended_community_evpn_subtype(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_T_FLOW_SPEC_REDIRECT_MIRROR_TO_IP_NEXT_HOP:
                sub_type_string = ""
            elif type == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE:
                sub_type_string = BGPTranslation.extended_community_t_generic_experimental(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE_PART2:
                sub_type_string = BGPTranslation.extended_community_t_generic_experimental_part2(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE_PART3:
                sub_type_string = BGPTranslation.extended_community_t_generic_experimental_part3(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_NT_TWO_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_nt_two_octet_as_subtype(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_NT_IPV4_ADDRESS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_nt_ipv4_address_subtype(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_NT_FOUR_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_nt_four_octet_as_subtype(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_NT_OPAQUE:
                sub_type_string = BGPTranslation.extended_community_nt_opaque(subtype)
            elif type == BGPStatics.EXT_COMMUNITY_NT_QOS_MARKING:
                sub_type_string = ""
            else:
                sub_type_string = "Unknown Sub-Type"

            return type_string + " " + sub_type_string
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community")
            logger.warning("Was not able to recognize input value for extended community translation.")

            return "Unknown Sub-Type"

    @staticmethod
    def extended_community_type(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_NT_TWO_OCTET_AS_SPECIFIC:
                return "Non-Transitive Two-Octet AS"
            elif value == BGPStatics.EXT_COMMUNITY_NT_IPV4_ADDRESS_SPECIFIC:
                return "Non-Transitive IPv4"
            elif value == BGPStatics.EXT_COMMUNITY_NT_FOUR_OCTET_AS_SPECIFIC:
                return "Non-Transitive Four-Octet AS"
            elif value == BGPStatics.EXT_COMMUNITY_NT_OPAQUE:
                return "Non-Transitive Opaque"
            elif value == BGPStatics.EXT_COMMUNITY_NT_QOS_MARKING:
                return "QoS Marking"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_SPECIFIC:
                return "Transitive Two-Octet AS"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_SPECIFIC:
                return "Transitive IPv4"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_SPECIFIC:
                return "Transitive Four-Octet AS"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE:
                return "Transitive Opaque"
            elif value == BGPStatics.EXT_COMMUNITY_T_QOS_MARKING:
                return "QoS Marking"
            elif value == BGPStatics.EXT_COMMUNITY_T_COS_CAPABILITY:
                return "CoS Capability"
            elif value == BGPStatics.EXT_COMMUNITY_T_EVPN:
                return "EVPN"
            elif value == BGPStatics.EXT_COMMUNITY_T_FLOW_SPEC_REDIRECT_MIRROR_TO_IP_NEXT_HOP:
                return "Flow spec redirect/mirror to IP next-hop"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE:
                return "Generic Transitive Experimental Use"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE_PART2:
                return "Generic Transitive Experimental Use (Part 2)"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE_PART3:
                return "Generic Transitive Experimental Use (Part 3)"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_type")
            logger.warning("Was not able to recognize input value for extended community type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_subtype(type, value):
        try:
            if type == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_t_two_octet_as_subtype(value)
            elif type == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_t_ipv4_address_subtype(value)
            elif type == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_t_four_octet_as_subtype(value)
            elif type == BGPStatics.EXT_COMMUNITY_T_OPAQUE:
                sub_type_string = BGPTranslation.extended_community_t_opaque(value)
            elif type == BGPStatics.EXT_COMMUNITY_T_QOS_MARKING:
                sub_type_string = ""
            elif type == BGPStatics.EXT_COMMUNITY_T_COS_CAPABILITY:
                sub_type_string = ""
            elif type == BGPStatics.EXT_COMMUNITY_T_EVPN:
                sub_type_string = BGPTranslation.extended_community_evpn_subtype(value)
            elif type == BGPStatics.EXT_COMMUNITY_T_FLOW_SPEC_REDIRECT_MIRROR_TO_IP_NEXT_HOP:
                sub_type_string = ""
            elif type == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE:
                sub_type_string = BGPTranslation.extended_community_t_generic_experimental(value)
            elif type == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE_PART2:
                sub_type_string = BGPTranslation.extended_community_t_generic_experimental_part2(value)
            elif type == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_USE_PART3:
                sub_type_string = BGPTranslation.extended_community_t_generic_experimental_part3(value)
            elif type == BGPStatics.EXT_COMMUNITY_NT_TWO_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_nt_two_octet_as_subtype(value)
            elif type == BGPStatics.EXT_COMMUNITY_NT_IPV4_ADDRESS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_nt_ipv4_address_subtype(value)
            elif type == BGPStatics.EXT_COMMUNITY_NT_FOUR_OCTET_AS_SPECIFIC:
                sub_type_string = BGPTranslation.extended_community_nt_four_octet_as_subtype(value)
            elif type == BGPStatics.EXT_COMMUNITY_NT_OPAQUE:
                sub_type_string = BGPTranslation.extended_community_nt_opaque(value)
            elif type == BGPStatics.EXT_COMMUNITY_NT_QOS_MARKING:
                sub_type_string = ""
            else:
                sub_type_string = "Unknown Sub-Type"

            return sub_type_string
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_subtype")
            logger.warning("Was not able to recognize input value for extended community subtype translation.")

            return "Unknown Sub-Type"

    @staticmethod
    def extended_community_evpn_subtype(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_EVPN_MAC_MOBILITY:
                return "MAC Mobility"
            elif value == BGPStatics.EXT_COMMUNITY_EVPN_ESI_LABEL:
                return "ESI Label"
            elif value == BGPStatics.EXT_COMMUNITY_EVPN_ES_IMPORT_ROUTE_TARGET:
                return "ES-Import Route Target"
            elif value == BGPStatics.EXT_COMMUNITY_EVPN_ROUTERS_MAC:
                return "EVPN Router's MAC Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_EVPN_LAYER2:
                return "Layer 2 Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_EVPN_ETREE:
                return "E-TREE Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_EVPN_DF_ELECTION:
                return "DF Election Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_EVPN_ISID:
                return "I-SID Extended Community"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_evpn_subtype")
            logger.warning("Was not able to recognize input value for extended community EVPN subtype translation.")

            return "Unknown"

    @staticmethod
    def extended_community_t_two_octet_as_subtype(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_ROUTE_TARGET:
                return "Route Target"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_ROUTE_ORIGIN:
                return "Route Origin"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_OSPF_DOMAIN_IDENTIFIER:
                return "OSPF Domain Identifier"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_BGP_DATA_COLLECTION:
                return "BGP Data Collection"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_SOURCE_AS:
                return "Source AS"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_L2VPN_IDENTIFIER:
                return "L2VPN Identifier"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_CISCO_VPN_DISTINGUISHER:
                return "Cisco VPN-Distinguisher"
            elif value == BGPStatics.EXT_COMMUNITY_T_TWO_OCTET_AS_ROUTE_TARGET_RECORD:
                return "Route-Target Record"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_t_two_octet_as_subtype")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_nt_two_octet_as_subtype(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_NT_TWO_OCTET_AS_LINK_BANDWIDTH:
                return "Link Bandwidth Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_NT_TWO_OCTET_AS_VIRTUAL_NETWORK_IDENTIFIER:
                return "Virtual-Network Identifier Extended Community"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_nt_two_octet_as_subtype")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_t_four_octet_as_subtype(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_ROUTE_TARGET:
                return "Route Target"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_ROUTE_ORIGIN:
                return "Route Origin"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_GENERIC:
                return "Generic"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_OSPF_DOMAIN_IDENTIFIER:
                return "OSPF Domain Identifier"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_BGP_DATA_COLLECTION:
                return "BGP Data Collection"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_SOURCE_AS:
                return "Source AS"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_CISCO_VPN_IDENTIFIER:
                return "Cisco VPN Identifier"
            elif value == BGPStatics.EXT_COMMUNITY_T_FOUR_OCTET_AS_ROUTE_TARGET_RECORD:
                return "Route-Target Record"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_t_four_octet_as_subtype")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_nt_four_octet_as_subtype(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_NT_FOUR_OCTET_AS_GENERIC:
                return "Generic"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_nt_four_octet_as_subtype")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_t_ipv4_address_subtype(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_ROUTE_TARGET:
                return "Route Target"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_ROUTE_ORIGIN:
                return "Route Origin"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_OSPF_DOMAIN_IDENTIFIER:
                return "OSPF Domain Identifier"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_OSPF_ROUTE_ID:
                return "OSPF Route ID"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_L2VPN_IDENTIFIER:
                return "L2VPN Identifier"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_VRF_ROUTE_IMPORT:
                return "VRF Route Import"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_FLOW_SPEC_REDIRECT_TO_IPV4:
                return "Flow-spec Redirect to IPv4"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_CISCO_VPN_DISTINGUISHER:
                return "Cisco VPN-Distinguisher"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_INTER_AREA_P2MP_SEGMENTED_NEXT_HOP:
                return "Inter-Area P2MP Segmented Next-Hop"
            elif value == BGPStatics.EXT_COMMUNITY_T_IPV4_ADDRESS_ROUTE_TARGET_RECORD:
                return "Route-Target-Record"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_t_ipv4_address_subtype")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_nt_ipv4_address_subtype(value):
        try:
            return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_nt_ipv4_address_subtype")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_t_opaque(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_COST_COMMUNITY:
                return "Cost Community"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_CP_ORF:
                return "CP-ORF"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_EXTRANET_SOURCE:
                return "Extranet Source Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_EXTRANET_SEPARATION:
                return "Extranet Separation Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_OSPF_ROUTE_TYPE:
                return "OSPF Route Type"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_ADDITIONAL_PMSI_TUNNEL_ATTRIBUTE_FLAGS:
                return "Additional PMSI Tunnel Attribute Flags"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_COLOR_EXTENDED:
                return "Color Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_ENCAPSULATION:
                return "Encapsulation Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_DEFAULT_GATEWAY:
                return "Default Gateway"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_PPMP_LABEL:
                return "Point-to-Point-to-Multipoint (PPMP) Label"
            elif value == BGPStatics.EXT_COMMUNITY_T_OPAQUE_CONSISTENT_HASH_SORT_ORDER:
                return "Consistent Hash Sort Order"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_t_opaque")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_nt_opaque(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_NT_OPAQUE_COST_COMMUNITY:
                return "Cost Community"
            elif value == BGPStatics.EXT_COMMUNITY_NT_OPAQUE_BGP_ORIGIN_VALIDATION_STATE:
                return "BGP Origin Validation State"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_nt_opaque")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_t_generic_experimental(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_OSPF_ROUTE_TYPE:
                return "OSPF Route Type"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_OSPF_ROUTER_ID:
                return "OSPF Router ID"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_OSPF_DOMAIN_IDENTIFIER:
                return "OSPF Domain Identifier"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_FLOW_SPEC_TRAFFIC_RATE:
                return "Flow spec traffic-rate"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_FLOW_SPEC_TRAFFIC_ACTION:
                return "Flow spec traffic-action"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_FLOW_SEPC_REDIRECT_AS_2BYTE_FORMAT:
                return "Flow spec redirect AS-2byte format"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_FLOW_SPEC_TRAFFIC_REMARKING:
                return "Flow spec traffic-remarking"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_LAYER2_INFO:
                return "Layer2 Info Extended Community"
            elif value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_E_TREE_INFO:
                return "E-Tree Info"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_t_generic_experimental")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_t_generic_experimental_part2(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_PART2_FLOW_SPEC_REDIRECT_IPV4_FORMAT:
                return "Flow spec redirect IPv4 format"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_t_generic_experimental_part2")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def extended_community_t_generic_experimental_part3(value):
        try:
            if value == BGPStatics.EXT_COMMUNITY_T_GENERIC_EXPERIMENTAL_PART3_FLOW_SPEC_AS_4BYTE_FORMAT:
                return "Flow spec redirect AS-4byte format"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.extended_community_t_generic_experimental_part3")
            logger.warning("Was not able to recognize input value for type translation.")

            return "Unknown"

    @staticmethod
    def path_segment_type(value):
        try:
            if value == BGPStatics.AS_PATH_SEGMENT_SEQUENCE:
                return "Sequence"
            elif value == BGPStatics.AS_PATH_SEGMENT_SET:
                return "Set"
            else:
                return "Unknown"
        except Exception as e:
            logger = logging.getLogger("pbgpp.BGPTranslation.path_segment_type")
            logger.warning("Was not able to recognize input value for path segment type translation.")

            return "Unknown"
