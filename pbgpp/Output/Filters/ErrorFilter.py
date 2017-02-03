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


class ErrorFilter(BGPFilter):
    def __init__(self, values=[]):
        BGPFilter.__init__(self, values)

    def apply(self, message):
        try:
            # Do not display messages that are containing an parsing error
            # @todo Also check attributes, capabilities, etc. for errors - not just the basis class
            if not message.error:
                return message
            else:
                return None
        except Exception as e:
            # On error the filtering was not successful (due to wrong fields, etc.)
            return None


