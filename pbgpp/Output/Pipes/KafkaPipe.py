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

from kafka import KafkaProducer
from kafka.errors import KafkaError

from pbgpp.BGP.Exceptions import BGPError
from pbgpp.Output.Pipe import BGPPipe


class KafkaPipe(BGPPipe):
    def __init__(self, server, topic):
        logger = logging.getLogger("pbgpp.KafkaPipe.__init__")

        # Kafka server initialization
        self.server = server
        self.topic = topic
        self.handle = None

        # Class specific variables
        try:
            self.handle = KafkaProducer(bootstrap_servers=[server])
        except Exception as e:
            logger.error("could not initialize connection to Apache Kafka server. Following exception has been reported: " + str(e))
            raise BGPError("Could not establish a connection to target pipe (Apache Kafka). Cancelling ...")

    def output(self, output):
        if self.handle is not None:
            if sys.version_info[0] < 3:
                self.handle.send(self.topic, output)
            else:
                self.handle.send(self.topic, bytes(output, "utf-8"))
