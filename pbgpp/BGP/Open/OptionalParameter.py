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

from pbgpp.BGP.Exceptions import BGPOptionalParameterFactoryError
from pbgpp.BGP.Statics import BGPStatics


class BGPOptionalParameter:

    def __init__(self, payload):
        self.payload = payload

        self.type = None
        self.error = None
        self.parsed = False

    @staticmethod
    def factory(parameter_type, payload):
        # Factory pattern for the optional parameters of OPEN message
        if parameter_type == BGPStatics.OPEN_CAPABILITY:
            from pbgpp.BGP.Open.Parameters.Capability import BGPOptionalParameterCapability
            return BGPOptionalParameterCapability(payload)

        if parameter_type == BGPStatics.OPEN_AUTHENTICATION:
            from pbgpp.BGP.Open.Parameters.Authentication import BGPOptionalParameterAuthentication
            return BGPOptionalParameterAuthentication(payload)

        if parameter_type == BGPStatics.OPEN_RESERVED:
            from pbgpp.BGP.Open.Parameters.Reserved import BGPOptionalParameterReserved
            return BGPOptionalParameterReserved(payload)

        # No type match
        raise BGPOptionalParameterFactoryError("given parameter type is not valid")
