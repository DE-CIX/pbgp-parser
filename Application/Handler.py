#
# This file is part of PCAP BGP Parser (pbgpp)
#
# Copyright 2016 DE-CIX Management GmbH
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
import sys
from itertools import chain

import pcapy

from BGP.Exceptions import BGPPacketHasNoMessagesError, BGPError
from BGP.Packet import BGPPacket
from Output.Filters.ASNFilter import ASNFilter
from Output.Filters.CommunityASNFilter import CommunityASNFilter
from Output.Filters.CommunityValueFilter import CommunityValueFilter
from Output.Filters.IPDestinationFilter import IPDestinationFilter
from Output.Filters.IPSourceFilter import IPSourceFilter
from Output.Filters.LastASNFilter import LastASNFilter
from Output.Filters.MACDestinationFilter import MACDestinationFilter
from Output.Filters.MACSourceFilter import MACSourceFilter
from Output.Filters.MessageSubTypeFilter import MessageSubTypeFilter
from Output.Filters.MessageTypeFilter import MessageTypeFilter
from Output.Filters.NLRIFilter import NLRIFilter
from Output.Filters.NextHopFilter import NextHopFilter
from Output.Filters.WithdrawnFilter import WithdrawnFilter
from Output.Formatters.HumanReadable import HumanReadableFormatter
from Output.Formatters.JSON import JSONFormatter
from Output.Formatters.LineBased import LineBasedFormatter
from Output.Handler import OutputHandler
from Output.Pipes.File import FilePipe
from Output.Pipes.Kafka import KafkaPipe
from Output.Pipes.StdOut import StdOutPipe
from PCAP.Ethernet import PCAPEthernet
from PCAP.IP import PCAPIP
from PCAP.Information import PCAPInformation
from PCAP.TCP import PCAPTCP


class PBGPPHandler:
    def __init__(self, parser):
        self.__parser = parser
        self.args = parser.parse_args()

        self.quiet = False
        self.verbose = False

        self.fields = None
        self.progress = False

        self.kafka_server = None
        self.kafka_topic = None

        self.formatter = None
        self.pipe = None
        self.filters = []
        self.prefilters = []

    def handle(self):
        if self.args.version:
            print("pbgpp PCAP BGP Parser v0.2.0")
            print("Copyright 2016 DE-CIX Management GmbH")
            sys.exit(0)

        if self.args.quiet:
            self.quiet = True

        if self.args.verbose:
            self.verbose = True

        if self.progress:
            self.progress = True

        self.__parse_filters()
        self.__parse_formatter()
        self.__parse_pipe()

        # Check for input method
        if self.args.interface:
            self.__handle_interface()
            sys.exit(0)

        if self.args.pcap:
            self.__handle_pcap()
            sys.exit(0)

        if self.args.stdin:
            self.__handle_stdin()
            sys.exit(0)

        self.__parser.print_help()
        sys.exit(0)

    def __parse_filters(self):
        if self.args.filter_message_type:
            values = self.args.filter_message_type
            filters = list(chain(*values))
            self.filters.append(MessageTypeFilter(filters))

        if self.args.filter_message_subtype:
            values = self.args.filter_message_subtype
            filters = list(chain(*values))
            self.filters.append(MessageSubTypeFilter(filters))

        if self.args.filter_nlri:
            values = self.args.filter_nlri
            filters = list(chain(*values))
            self.filters.append(NLRIFilter(filters))

        if self.args.filter_withdrawn:
            values = self.args.filter_withdrawn
            filters = list(chain(*values))
            self.filters.append(WithdrawnFilter(filters))

        if self.args.filter_next_hop:
            values = self.args.filter_next_hop
            filters = list(chain(*values))
            self.filters.append(NextHopFilter(filters))

        if self.args.filter_asn:
            values = self.args.filter_asn
            filters = list(chain(*values))
            self.filters.append(ASNFilter(filters))

        if self.args.filter_last_asn:
            values = self.args.filter_last_asn
            filters = list(chain(*values))
            self.filters.append(LastASNFilter(filters))

        if self.args.filter_community_as:
            values = self.args.filter_community_as
            filters = list(chain(*values))
            self.filters.append(CommunityASNFilter(filters))

        if self.args.filter_community_value:
            values = self.args.filter_community_value
            filters = list(chain(*values))
            self.filters.append(CommunityValueFilter(filters))

        if self.args.filter_source_ip:
            values = self.args.filter_source_ip
            filters = list(chain(*values))
            self.prefilters.append(IPSourceFilter(filters))

        if self.args.filter_destination_ip:
            values = self.args.filter_destination_ip
            filters = list(chain(*values))
            self.prefilters.append(IPDestinationFilter(filters))

        if self.args.filter_source_mac:
            values = self.args.filter_source_mac
            filters = list(chain(*values))
            self.prefilters.append(MACSourceFilter(filters))

        if self.args.filter_destination_mac:
            values = self.args.filter_destination_mac
            filters = list(chain(*values))
            self.prefilters.append(MACDestinationFilter(filters))

    def __parse_formatter(self):
        if self.args.formatter == "JSON":
            self.formatter = JSONFormatter()
        elif self.args.formatter == "HUMAN_READABLE":
            self.formatter = HumanReadableFormatter()
        elif self.args.formatter == "LINE":
            values = self.args.fields.split(",")
            self.formatter = LineBasedFormatter(fields=values)
        else:
            self.__parser.error("Can't recognize the formatter.")

    def __parse_pipe(self):
        if self.args.pipe == "FILE":
            if self.args.output_target is None:
                self.__parser.error("You need to specify the output target (-o / --output) when using FILE as pipe.")
            self.pipe = FilePipe(self.args.output_target)
        elif self.args.pipe == "STDOUT":
            self.pipe = StdOutPipe()
        elif self.args.pipe == "KAFKA":
            self.pipe = KafkaPipe()
        else:
            self.__parser.error("Can't recognize the output pipe.")

    def __handle_interface(self):
        raise NotImplemented

    def __handle_pcap(self):
        handle = pcapy.open_offline(self.args.pcap)
        handle.loop(0, self.__packet_handler)

    def __handle_stdin(self):
        handle = pcapy.open_offline("-")
        handle.loop(0, self.__packet_handler)

    def __packet_handler(self, header, payload):
        eth = PCAPEthernet(payload)

        if not eth.get_type() == PCAPEthernet.ETH_TYPE_IPV4:
            return False

        ip = PCAPIP(eth.get_eth_payload())

        if not ip.get_protocol() == PCAPIP.PROTO_TCP:
            return False

        tcp = PCAPTCP(ip.get_ip_payload())

        pcap_information = PCAPInformation(header.getts(), eth.mac, ip.addresses, tcp.ports)

        for filter in self.prefilters:
            if not filter.apply(pcap_information):
                return

        try:
            bgp = BGPPacket(tcp.get_tcp_payload(), pcap_information)

            messages = bgp.message_list

            for m in messages:
                handler = OutputHandler(message=m, filter=self.filters, formatter=self.formatter, pipe=self.pipe)
                handler.handle()

        except BGPPacketHasNoMessagesError:
            pass
        except BGPError:
            pass
