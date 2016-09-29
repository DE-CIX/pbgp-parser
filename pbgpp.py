#!/usr/bin/env python
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

import argparse
import logging

from Application.Handler import PBGPPHandler

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

parser = argparse.ArgumentParser(description="detailed bgp packet message parsing from PCAP files or direct network traffic")

parser.add_argument("-f", "--formatter", help="specify data output format", choices=['JSON', 'HUMAN_READABLE', 'LINE'], default="HUMAN_READABLE", dest="formatter")
parser.add_argument("-p", "--pipe", help="specify output type of parsed messages", choices=['FILE', 'STDOUT', 'KAFKA'], default="STDOUT", dest="pipe")
parser.add_argument("-o", "--output", help="specify target output file if your output type is set to FILE", dest="output_target")

group_1 = parser.add_mutually_exclusive_group()
group_1.add_argument("--interface", help="use a network interface as input source (specify interface)", dest="interface")
group_1.add_argument("--pcap", help="use a pcap file as input source (specify file)", dest="pcap")
group_1.add_argument("--stdin", help="use stdin as input source", dest="stdin", action="store_true")

group_2 = parser.add_mutually_exclusive_group()
group_2.add_argument("-q", "--quiet", help="just show parsing output", action="store_true", dest="quiet")
group_2.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true", dest="verbose")

group_3 = parser.add_argument_group("kafka configuration")
group_3.add_argument("--kafka-server", help="IP address and port of the target kafka server if your output type is set to KAFKA", dest="kafka_server")
group_3.add_argument("--kafka-topic", help="topic of kafka server if your output type is set to KAFKA", dest="kafka_topic")

group_4 = parser.add_argument_group("filters")
group_4.add_argument("--filter-message-type", help="just print packages with given message type (KEEPALIVE, NOTIFICATION, OPEN, ROUTE-REFRESH, UPDATE, WITHDRAWAL)", nargs="+", action="append", dest="filter_message_type")
group_4.add_argument("--filter-message-subtype", help="just print UPDATE messages with given message sub type (WITHDRAWAL, ANNOUNCE, BOTH, NONE)", nargs="+", action="append", dest="filter_message_subtype")
group_4.add_argument("--filter-nlri", help="just print packages with given nlri prefix into it (e.g. '80.81.82.0/24'", nargs="+", action="append", dest="filter_nlri")
group_4.add_argument("--filter-withdrawn", help="just print packages with given withdrawn routes (e.g. '80.81.82.0/24'", nargs="+", action="append", dest="filter_withdrawn")
group_4.add_argument("--filter-next-hop", help="just print packages with given next hop (e.g. '80.81.82.83')", nargs="+", action="append", dest="filter_next_hop")
group_4.add_argument("--filter-as", help="just print packages with given ASN in path AS_PATH attribute (e.g. '12345')", nargs="+", action="append", dest="filter_asn")
group_4.add_argument("--filter-last-as", help="just print packages with given ASN as last ASN in AS_PATH attribute (e.g. '12345')", nargs="+", action="append", dest="filter_last_asn")
group_4.add_argument("--filter-community-as", help="just print packages with given community ASN (e.g. '12345')", nargs="+", action="append", dest="filter_community_as")
group_4.add_argument("--filter-community-value", help="just print packages with given community value (e.g. '12345')", nargs="+", action="append", dest="filter_community_value")
group_4.add_argument("--filter-source-ip", help="just print packages with given source IP address (e.g. '80.81.82.83')", nargs="+", action="append", dest="filter_source_ip")
group_4.add_argument("--filter-source-mac", help="just print packages with given source MAC address (e.g. 'aa:bb:cc:dd:ee:ff')", nargs="+", action="append", dest="filter_source_mac")
group_4.add_argument("--filter-destination-ip", help="just print packages with given destination IP address (e.g. '80.81.82.83')", nargs="+", action="append", dest="filter_destination_ip")
group_4.add_argument("--filter-destination-mac", help="just print packages with given destination MAC address (e.g. 'aa:bb:cc:dd:ee:ff')", nargs="+", action="append", dest="filter_destination_mac")

group_5 = parser.add_argument_group("line output commands")
group_5.add_argument("--fields", help="specify the output-fields you wish to display in the order you want; separated by comma", dest="fields", default="update.nlri,update.as_path,update.next_hop,ip.source,ip.destination,update.communities")

group_6 = parser.add_argument_group("other commands")
group_6.add_argument("--version", help="displays the current version of this software", action="store_true", dest="version")
group_6.add_argument("--progress", help="displays the current progress - only applicable when using pcap file as input source and writing to file or Kafka", action="store_true", dest="progress")

main_handler = PBGPPHandler(parser)

try:
    main_handler.handle()
except Exception as e:
    print("ERROR: " + str(e))
except KeyboardInterrupt:
    print("Exit execution due to keyboard interruption.")