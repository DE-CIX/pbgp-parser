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

from pbgpp.BGP.Open.OptionalParameter import BGPOptionalParameter
from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation


class BGPOptionalParameterReserved(BGPOptionalParameter):

    def __init__(self, payload):
        BGPOptionalParameter.__init__(self, payload)
        self.type = BGPStatics.OPEN_RESERVED
        self.__parse()

    def __parse(self):
        self.parsed = True

    def json(self):
        return {
            "type": self.type,
            "type_string": BGPTranslation.open_parameter(self.type)
        }
