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
import sys
import os.path
import glob
from itertools import chain

import pcapy

from pbgpp.BGP.Exceptions import BGPPacketHasNoMessagesError, BGPError
from pbgpp.BGP.Packet import BGPPacket
from pbgpp.Output.Filters.ASNFilter import ASNFilter
from pbgpp.Output.Filters.CommunityASNFilter import CommunityASNFilter
from pbgpp.Output.Filters.CommunityValueFilter import CommunityValueFilter
from pbgpp.Output.Filters.LargeCommunityFilter import LargeCommunityFilter
from pbgpp.Output.Filters.IPDestinationFilter import IPDestinationFilter
from pbgpp.Output.Filters.IPSourceFilter import IPSourceFilter
from pbgpp.Output.Filters.LastASNFilter import LastASNFilter
from pbgpp.Output.Filters.MACDestinationFilter import MACDestinationFilter
from pbgpp.Output.Filters.MACSourceFilter import MACSourceFilter
from pbgpp.Output.Filters.MessageSizeFilter import MessageSizeFilter
from pbgpp.Output.Filters.MessageSubTypeFilter import MessageSubTypeFilter
from pbgpp.Output.Filters.MessageTypeFilter import MessageTypeFilter
from pbgpp.Output.Filters.NLRIFilter import NLRIFilter
from pbgpp.Output.Filters.NextHopFilter import NextHopFilter
from pbgpp.Output.Filters.TimestampFilter import TimestampFilter
from pbgpp.Output.Filters.WithdrawnFilter import WithdrawnFilter
from pbgpp.Output.Formatters.HumanReadable import HumanReadableFormatter
from pbgpp.Output.Formatters.JSON import JSONFormatter
from pbgpp.Output.Formatters.LineBased import LineBasedFormatter
from pbgpp.Output.Handler import OutputHandler
from pbgpp.Output.Pipes.FilePipe import FilePipe
from pbgpp.Output.Pipes.KafkaPipe import KafkaPipe
from pbgpp.Output.Pipes.StdOutPipe import StdOutPipe
from pbgpp.PCAP.CookedCapture import PCAPCookedCapture
from pbgpp.PCAP.Ethernet import PCAPEthernet
from pbgpp.PCAP.IP import PCAPIP
from pbgpp.PCAP.Information import PCAPInformation
from pbgpp.PCAP.TCP import PCAPTCP


class PBGPPHandler:
    def __init__(self, parser):
        self.__parser = parser
        self.args = parser.parse_args()

        self.quiet = False
        self.verbose = False

        self.fields = None

        self.kafka_server = None
        self.kafka_topic = None

        self.formatter = None
        self.pipe = None
        self.filters = []
        self.prefilters = []

        self.__packet_counter = 0

    def handle(self):
        logger = logging.getLogger('pbgpp.PBGPPHandler.handle')

        if self.args.version:
            print("pbgpp PCAP BGP Parser v0.2.17")
            print("Copyright 2016-2017, DE-CIX Management GmbH")
            sys.exit(0)

        if self.args.quiet:
            # 60 is higher then CRITICAL log level
            logging.getLogger().setLevel(60)

        if self.args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        logger.debug("Parsing filters ...")
        self.__parse_filters()

        logger.debug("Parsing formatters ...")
        self.__parse_formatter()

        logger.debug("Parsing pipes ...")
        self.__parse_pipe()

        # Check for input method
        if self.args.interface:
            logger.info("Initial startup finished. Calling interface handler ...")
            self.__handle_interface()
            logger.info("Parsing finished - Exiting now with status code 0")
            sys.exit(0)

        if self.args.pcap:
            logger.info("Initial startup finished. Calling pcap handler ...")
            self.__handle_pcap()
            logger.info("Parsing finished - Exiting now with status code 0")
            sys.exit(0)

        if self.args.stdin:
            logger.info("Initial startup finished. Calling stdin handler ...")
            self.__handle_stdin()
            logger.info("Parsing finished - Exiting now with status code 0")
            sys.exit(0)

        self.__parser.print_help()
        sys.exit(0)

    def __parse_filters(self):
        logger = logging.getLogger("pbgpp.PBGPPHandler.__parse_filters")

        if self.args.filter_message_type:
            values = self.args.filter_message_type
            filters = list(chain(*values))
            self.filters.append(MessageTypeFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of MessageTypeFilter")

        if self.args.filter_message_subtype:
            values = self.args.filter_message_subtype
            filters = list(chain(*values))
            self.filters.append(MessageSubTypeFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of MessageSubTypeFilter")

        if self.args.filter_nlri:
            values = self.args.filter_nlri
            filters = list(chain(*values))
            self.filters.append(NLRIFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of NLRIFilter")

        if self.args.filter_withdrawn:
            values = self.args.filter_withdrawn
            filters = list(chain(*values))
            self.filters.append(WithdrawnFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of WithdrawnFilter")

        if self.args.filter_next_hop:
            values = self.args.filter_next_hop
            filters = list(chain(*values))
            self.filters.append(NextHopFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of NextHopFilter")

        if self.args.filter_asn:
            values = self.args.filter_asn
            filters = list(chain(*values))
            self.filters.append(ASNFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of ASNFilter")

        if self.args.filter_last_asn:
            values = self.args.filter_last_asn
            filters = list(chain(*values))
            self.filters.append(LastASNFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of LastASNFilter")

        if self.args.filter_community_as:
            values = self.args.filter_community_as
            filters = list(chain(*values))
            self.filters.append(CommunityASNFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of CommunityASNFilter")

        if self.args.filter_community_value:
            values = self.args.filter_community_value
            filters = list(chain(*values))
            self.filters.append(CommunityValueFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of CommunityValueFilter")

        if self.args.filter_large_community:
            values = self.args.filter_large_community
            filters = list(chain(*values))
            self.filters.append(LargeCommunityFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of LargeCommunityFilter")

        if self.args.filter_message_size:
            values = self.args.filter_message_size
            filters = list(chain(*values))
            self.filters.append(MessageSizeFilter(filters))
            logger.debug("Added " + str(len(filters)) + " filter(s) of MessageSizeFilter")

        if self.args.filter_source_ip:
            values = self.args.filter_source_ip
            filters = list(chain(*values))
            self.prefilters.append(IPSourceFilter(filters))
            logger.debug("Added " + str(len(filters)) + " pre-filter(s) of IPSourceFilter")

        if self.args.filter_destination_ip:
            values = self.args.filter_destination_ip
            filters = list(chain(*values))
            self.prefilters.append(IPDestinationFilter(filters))
            logger.debug("Added " + str(len(filters)) + " pre-filter(s) of IPDestinationFilter")

        if self.args.filter_source_mac:
            values = self.args.filter_source_mac
            filters = list(chain(*values))
            self.prefilters.append(MACSourceFilter(MACSourceFilter.clear_input(filters)))
            logger.debug("Added " + str(len(filters)) + " pre-filter(s) of MACSourceFilter")

        if self.args.filter_destination_mac:
            values = self.args.filter_destination_mac
            filters = list(chain(*values))
            self.prefilters.append(MACDestinationFilter(MACSourceFilter.clear_input(filters)))
            logger.debug("Added " + str(len(filters)) + " pre-filter(s) of MACDestinationFilter")

        if self.args.filter_timestamp:
            values = self.args.filter_timestamp
            filters = list(chain(*values))
            self.prefilters.append(TimestampFilter(filters))
            logger.debug("Added " + str(len(filters)) + " pre-filter(s) of TimestampFilter")

    def __parse_formatter(self):
        if self.args.formatter == "JSON":
            self.formatter = JSONFormatter()
        elif self.args.formatter == "HUMAN_READABLE":
            self.formatter = HumanReadableFormatter()
        elif self.args.formatter == "LINE":
            values = self.args.fields.split(",")

            for v in values:
                if not LineBasedFormatter.is_registered(v):
                    self.__parser.error("Could not recognize field '" + str(v) + "' for line based output. Use --help argument to see all available fields.")

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
            if self.args.kafka_server is None or self.args.kafka_topic is None:
                self.__parser.error("You need to specify Kafka server (--kafka-server) and topic (--kafka-topic) when using KAFKA as output pipe.")
            self.pipe = KafkaPipe(server=self.args.kafka_server, topic=self.args.kafka_topic)
        else:
            self.__parser.error("Can't recognize the output pipe.")

    def __handle_interface(self):
        # This is experimental! Not verified, yet.
        handle = pcapy.open_live(self.args.interface, 65536, 1, 0)
        handle.loop(0, self.__packet_handler)

    def __handle_pcap(self):
        logger = logging.getLogger("pbgpp.PBGPPHandler.__handle_pcap")

        if os.path.isfile(self.args.pcap):
            handle = pcapy.open_offline(self.args.pcap)
            handle.loop(0, self.__packet_handler)
        else:
            logger.info("Given PCAP input string is not direct path to a single file. Checking for glob-argument.")

            files = glob.glob(self.args.pcap)
            if len(files) == 0:
                logger.warning("Tried to use glob() on provided --pcap argument but list size is zero.")
                self.__parser.error("Specified --pcap argument is neither a single file nor a valid wildcard string (no files found!)")

            for f in files:
                logger.debug("Handling file: " + str(f))
                handle = pcapy.open_offline(f)
                handle.loop(0, self.__packet_handler)

    def __handle_stdin(self):
        handle = pcapy.open_offline("-")
        handle.loop(0, self.__packet_handler)

    def __packet_handler(self, header, payload):
        logger = logging.getLogger("pbgpp.PBGPPHandler.__packet_handler")
        logger.debug("Parsing PCAP packet " + str(self.__packet_counter))

        eth = PCAPEthernet(payload)

        # Check for raw ethernet packet
        if not eth.get_type() == PCAPEthernet.ETH_TYPE_IPV4:

            # Check for SLL-packet
            eth = PCAPCookedCapture(payload)

            if not eth.get_type() == PCAPCookedCapture.ETH_TYPE_IPV4:
                logger.debug("Discarding PCAP packet " + str(self.__packet_counter) + " due to non-IPv4 ethernet type.")
                return False

        ip = PCAPIP(eth.get_eth_payload())

        if not ip.get_protocol() == PCAPIP.PROTO_TCP:
            logger.debug("Discarding PCAP packet " + str(self.__packet_counter) + " due to non-TCP IP type.")
            return False

        tcp = PCAPTCP(ip.get_ip_payload())

        pcap_information = PCAPInformation(header.getts(), eth.mac, ip.addresses, tcp.ports)

        for filter in self.prefilters:
            if not filter.apply(pcap_information):
                logger.debug("Discarding PCAP packet " + str(self.__packet_counter) + " because no applied pre-filter could be matched.")
                return

        try:
            bgp = BGPPacket(tcp.get_tcp_payload(), pcap_information)

            messages = bgp.message_list

            for m in messages:
                handler = OutputHandler(message=m, filter=self.filters, formatter=self.formatter, pipe=self.pipe)
                handler.handle()

        except BGPPacketHasNoMessagesError:
            # This is no problem because a PCAP file could also contain TCP control packets. Those packets obviously do not contain any BGP information.
            logger.debug("BGPPacket which was assembled from PCAP packet " + str(self.__packet_counter) + " did not contain any BGP messages.")
        except BGPError:
            logger.error("Unspecified BGPError was raised while handling BGPPacket which was assembled from PCAP packet " + str(self.__packet_counter) + ".")
        finally:
            self.__packet_counter += 1
