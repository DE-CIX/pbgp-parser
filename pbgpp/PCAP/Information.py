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

from binascii import hexlify

import datetime

from pbgpp.PCAP.Exceptions import PCAPInformationError


class PCAPInformation:
    def __init__(self, ts, mac, ip, ports):
        if not isinstance(mac, PCAPLayer2Information):
            raise PCAPInformationError("parameter 'mac' must be instance of PCAPLayer2Information")

        if not isinstance(ip, PCAPLayer3Information):
            raise PCAPInformationError("parameter 'ip' must be instance of PCAPLayer3Information")

        if not isinstance(ports, PCAPLayer4Information):
            raise PCAPInformationError("parameter 'ports' must be instance of PCAPLayer4Information")

        # Assign variables
        self.ts = ts # (Timestamp)
        self.mac = mac # (MAC address set)
        self.ip = ip # (IP address set)
        self.ports = ports # (Port set)

    def get_timestamp(self):
        return self.ts

    def get_timestmap_utc(self):
        return datetime.datetime.utcfromtimestamp(self.ts[0]).strftime('%Y-%m-%d %H:%M:%S') + "." + str(self.ts[1])

    def get_mac(self):
        return self.mac

    def get_ip(self):
        return self.ip

    def get_ports(self):
        return self.ports

    def get_source_mac(self):
        return self.mac.source

    def get_source_ip(self):
        return self.ip.source

    def get_source_port(self):
        return self.ports.source

    def get_destination_mac(self):
        return self.mac.destination

    def get_destination_ip(self):
        return self.ip.destination

    def get_destination_port(self):
        return self.ports.destination


class PCAPLayer2Information:
    def __init__(self, source, destination):
        # Store source and destination MAC address
        self.source = source
        self.destination = destination

    def get_source_string(self, separated=False):
        if self.source is None:
            output = "000000000000"
        else:
            output = str(hexlify(self.source).decode("utf-8"))

        if separated:
            return output[0:2] + ":" + output[2:4] + ":" + output[4:6] + ":" + output[6:8] + ":" + output[8:10] + ":" + output[10:12]
        else:
            return output

    def get_destination_string(self, separated=False):
        if self.destination is None:
            output = "000000000000"
        else:
            output = str(hexlify(self.destination).decode("utf-8"))

        if separated:
            return output[0:2] + ":" + output[2:4] + ":" + output[4:6] + ":" + output[6:8] + ":" + output[8:10] + ":" + output[10:12]
        else:
            return output

    def __str__(self):
        return "<PCAPLayer2Information source={0} destination={1}>".format(self.get_source_string(), self.get_destination_string())


class PCAPLayer3Information:
    def __init__(self, source, destination):
        # Store source and destination IP address
        self.source = source
        self.destination = destination

    def get_source_string(self):
        return str(self.source[0]) + "." + str(self.source[1]) + "." + str(self.source[2]) + "." + str(self.source[3])

    def get_destination_string(self):
        return str(self.destination[0]) + "." + str(self.destination[1]) + "." + str(self.destination[2]) + "." + str(self.destination[3])

    def __str__(self):
        return "<PCAPLayer3Information source={0} destination={1}>".format(self.get_source_string(), self.get_destination_string())


class PCAPLayer4Information:
    def __init__(self, source, destination):
        # Store source and destination port
        self.source = source
        self.destination = destination

    def get_source_string(self):
        return str(self.source)

    def get_destination_string(self):
        return str(self.destination)

    def __str__(self):
        return "<PCAPLayer4Information source={0} destination={1}>".format(self.get_source_string(), self.get_destination_string())
