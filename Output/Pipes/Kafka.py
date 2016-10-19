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
from kafka import KafkaProducer

from Output.Pipe import BGPPipe


class KafkaPipe(BGPPipe):
    def __init__(self, server, topic):
        # Kafka server initialization
        self.server = server
        self.topic = topic

        # Class specific variables
        self.handle = KafkaProducer(bootstrap_servers=server)

    def __del__(self):
        try:
            self.handle.flush()
            self.handle.close()
        except Exception as e:
            # Could not gracefully shutdown Kafka connection
            pass

    def output(self, output):
        self.handle.send(self.topic, output)
