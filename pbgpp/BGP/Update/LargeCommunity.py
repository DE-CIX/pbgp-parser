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

import struct


class BGPUpdateLargeCommunity:
    def __init__(self, global_administrator, local_data_part_1, local_data_part_2):
        self.global_administrator = global_administrator
        self.local_data_part_1 = local_data_part_1
        self.local_data_part_2 = local_data_part_2

    def _get_four_octect_values_as_str(self):
        if isinstance(self.global_administrator, int) and isinstance(self.local_data_part_1, int) and isinstance(self.local_data_part_2, int):
            return str(self.global_administrator), str(self.local_data_part_1), str(self.local_data_part_2)
        elif isinstance(self.global_administrator, bytes) and isinstance(self.local_data_part_1, bytes) and isinstance(self.local_data_part_2, bytes):
            global_administrator = str(struct.unpack("!L", self.global_administrator)[0])
            local_data_part_1 = str(struct.unpack("!L", self.local_data_part_1)[0])
            local_data_part_2 = str(struct.unpack("!L", self.local_data_part_2)[0])
            return global_administrator, local_data_part_1, local_data_part_2
        else:
            return None

    def __str__(self):
        four_octect_values = self._get_four_octect_values_as_str()

        if four_octect_values:
            return "{}:{}:{}".format(
                four_octect_values[0],
                four_octect_values[1],
                four_octect_values[2]
            )
        else:
            return None

    def json(self):
        four_octect_values = self._get_four_octect_values_as_str()

        if four_octect_values:
            return {
                "global_administrator": four_octect_values[0],
                "local_data_part_1": four_octect_values[1],
                "local_data_part_2": four_octect_values[2]
            }
        else:
            return None
