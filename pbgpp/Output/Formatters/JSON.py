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

import json

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation
from pbgpp.Output.Formatter import BGPFormatter


class JSONFormatter(BGPFormatter):
    def __init__(self):
        pass

    def apply(self, message):

        # Basic data for every message type
        data = {
            "timestamp": str(message.pcap_information.get_timestamp()[0]) + "." + str(message.pcap_information.get_timestamp()[1]),

            "message_type": message.type,
            "message_type_string": BGPTranslation.message_type(message.type),
            "length": message.length,

            "source_mac": message.pcap_information.get_mac().get_source_string(),
            "destination_mac": message.pcap_information.get_mac().get_destination_string(),
            "source_ip": message.pcap_information.get_ip().get_source_string(),
            "destination_ip": message.pcap_information.get_ip().get_destination_string(),

            "message_data": None
        }

        # Handle specific message types that contain more information than added above
        # Currently we just need to add information to OPEN- and UPDATE-messages
        if message.type == BGPStatics.MESSAGE_TYPE_OPEN:
            message_data = {
                "asn": message.asn,
                "hold_time": message.hold_time,
                "identifier": message.identifier,
                "optional_parameter_length": message.optional_parameter_length,

                "optional_parameters": None
            }

            # Add optional parameters
            optional_parameters = []

            if len(message.optional_parameter) > 0:
                for o in message.optional_parameter:
                    optional_parameters.append(o.json())

            # Assign to message data
            message_data["optional_parameters"] = optional_parameters

            # Assign message data to return data
            data["message_data"] = message_data

        elif message.type == BGPStatics.MESSAGE_TYPE_UPDATE:
            message_data = {
                "sub_type_string": BGPTranslation.update_subtype(message.subtype),
                "withdrawn_routes_length": message.withdrawn_routes_length,
                "path_attributes_length": message.path_attributes_length,

                "path_attributes": None,
                "withdrawn_routes": None,
                "nlri": None
            }

            path_attributes = []
            withdrawn_routes = []
            nlri = []

            # Add path attributes
            if len(message.path_attributes) > 0:
                for a in message.path_attributes:
                    path_attributes.append(a.json())

            # Add withdrawn routes
            if len(message.withdrawn_routes) > 0:
                for w in message.withdrawn_routes:
                    withdrawn_routes.append(str(w))

            # Add NLRI
            if len(message.nlri) > 0:
                for n in message.nlri:
                    nlri.append(str(n))

            # Assign to message data
            message_data["path_attributes"] = path_attributes
            message_data["withdrawn_routes"] = withdrawn_routes
            message_data["nlri"] = nlri

            # Assign message data to return data
            data["message_data"] = message_data

        return json.dumps(data)
