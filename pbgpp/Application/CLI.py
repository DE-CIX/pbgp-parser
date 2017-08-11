#!/usr/bin/env python
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

import argparse
import logging

import sys

from pbgpp.Application.Handler import PBGPPHandler
from pbgpp.Output.Formatters.LineBased import LineBasedFormatter


def main():
    logger = logging.getLogger('pbgpp')
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logging.getLogger().setLevel(logging.ERROR)

    parser = argparse.ArgumentParser(description="detailed bgp packet message parsing from PCAP files or direct network traffic")

    parser.add_argument("-f", "--formatter", help="specify data output format", choices=['JSON', 'HUMAN_READABLE', 'LINE'], default="HUMAN_READABLE", dest="formatter")
    parser.add_argument("-p", "--pipe", help="specify output target type of parsed messages", choices=['FILE', 'STDOUT', 'KAFKA'], default="STDOUT", dest="pipe")
    parser.add_argument("-o", "--output", help="specify target output file if your output type is set to FILE", dest="output_target")

    group_1 = parser.add_mutually_exclusive_group()
    group_1.add_argument("--interface", help="use a network interface as input  (specify interface)", dest="interface")
    group_1.add_argument("--pcap", help="use a pcap file as input (specify file)", dest="pcap")
    group_1.add_argument("--stdin", "-", help="use stdin as input", dest="stdin", action="store_true")

    group_2 = parser.add_mutually_exclusive_group()
    group_2.add_argument("-q", "--quiet", help="only show parsing output", action="store_true", dest="quiet")
    group_2.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true", dest="verbose")

    group_3 = parser.add_argument_group("kafka configuration")
    group_3.add_argument("--kafka-server", help="IP address / hostname (and port if it's different from 9092) of the target Apache Kafka server if your output type is set to KAFKA (e.g. 127.0.0.1:9092)", dest="kafka_server")
    group_3.add_argument("--kafka-topic", help="topic of Apache Kafka server if your output type is set to KAFKA (e.g. pbgpp)", dest="kafka_topic")

    group_4 = parser.add_argument_group("filters")
    group_4.add_argument("--filter-timestamp", help="only print messages with given epoch timestamp (e.g., 123456789)", nargs="+", action="append", dest="filter_timestamp")
    group_4.add_argument("--filter-message-size", help="only print messages with given message size in bytes (e.g., 128)", nargs="+", action="append", dest="filter_message_size")
    group_4.add_argument("--filter-message-type", help="only print messages with given BGP message type (KEEPALIVE, NOTIFICATION, OPEN, ROUTE-REFRESH, UPDATE, WITHDRAWAL)", nargs="+", action="append", dest="filter_message_type")
    group_4.add_argument("--filter-message-subtype", help="only print UPDATE messages with given message sub type (WITHDRAWAL, ANNOUNCE, BOTH, NONE)", nargs="+", action="append", dest="filter_message_subtype")
    group_4.add_argument("--filter-nlri", help="only print messages containing the given nlri prefix (e.g., '80.81.82.0/24'", nargs="+", action="append", dest="filter_nlri")
    group_4.add_argument("--filter-withdrawn", help="only print messages containing the given withdrawn routes (e.g., '80.81.82.0/24'", nargs="+", action="append", dest="filter_withdrawn")
    group_4.add_argument("--filter-next-hop", help="only print messages containing the given next hop (e.g., '80.81.82.83')", nargs="+", action="append", dest="filter_next_hop")
    group_4.add_argument("--filter-as", help="only print messages containing the given ASN in path AS_PATH attribute (e.g., '12345')", nargs="+", action="append", dest="filter_asn")
    group_4.add_argument("--filter-last-as", help="only print messages containing the given ASN as last ASN in AS_PATH attribute (e.g., '12345')", nargs="+", action="append", dest="filter_last_asn")
    group_4.add_argument("--filter-community-as", help="only print messages containing the given community ASN (e.g., '12345')", nargs="+", action="append", dest="filter_community_as")
    group_4.add_argument("--filter-community-value", help="only print messages containing the given community value (e.g., '12345')", nargs="+", action="append", dest="filter_community_value")
    group_4.add_argument("--filter-source-ip", help="only print messages containing the given source IP address (e.g., '80.81.82.83')", nargs="+", action="append", dest="filter_source_ip")
    group_4.add_argument("--filter-source-mac", help="only print messages containing the given source MAC address (e.g., 'aabbccddeeff')", nargs="+", action="append", dest="filter_source_mac")
    group_4.add_argument("--filter-destination-ip", help="only print messages containing the given destination IP address (e.g., '80.81.82.83')", nargs="+", action="append", dest="filter_destination_ip")
    group_4.add_argument("--filter-destination-mac", help="only print messages containing the given destination MAC address (e.g., 'aabbccddeeff')", nargs="+", action="append", dest="filter_destination_mac")
    group_4.add_argument("--filter-large-community", help="only print messages containing one or more matching large communities (e.g., '11:22:33', '11:*:*', '*:22:33')", nargs="+", action="append", dest="filter_large_community")

    group_5 = parser.add_argument_group("line output commands")
    group_5.add_argument("--fields", help="specify the output-fields to be display in the order desired; separated by comma. Available fields are: " + LineBasedFormatter.available_fields(), dest="fields", default=LineBasedFormatter.FIELD_MESSAGE_TIMESTAMP[0] + "," + LineBasedFormatter.FIELD_MESSAGE_TYPE[0] + "," + LineBasedFormatter.FIELD_UPDATE_SUBTYPE[0] + "," + LineBasedFormatter.FIELD_UPDATE_NLRI[0] + "," + LineBasedFormatter.FIELD_UPDATE_WITHDRAWN_ROUTES[0])

    group_6 = parser.add_argument_group("other commands")
    group_6.add_argument("--version", help="displays the current version of this software", action="store_true", dest="version")

    main_handler = PBGPPHandler(parser)

    try:
        main_handler.handle()
    except Exception as e:
        logger.error("Main error handler has received an exception: " + str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt - terminating ...")
        print("Exit execution due to keyboard interruption.")
        sys.exit(0)
