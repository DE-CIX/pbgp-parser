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

from pbgpp.Output.Filter import BGPFilter


class IPSourceFilter(BGPFilter):
    def __init__(self, values=[]):
        BGPFilter.__init__(self, values)

    def apply(self, pcap_information):
        # !!! Attention: This is a pre-parsing filter!
        # This filter must be applied BEFORE parsing, otherwise it will unnecessarily slow down
        # the whole application. BGP messages don't have to be parsed when applying that filter
        # directly after reading PCAP packet header

        try:
            for v in self.values:
                if pcap_information.get_ip().get_source_string() == v:
                    return True

                if v[0:1] == "~" and pcap_information.get_ip().get_source_string() != v[1:]:
                    return True

            # Searched value was not found
            return False
        except Exception as e:
            # On error the filtering was not successful (due to wrong fields, etc.)
            return False
