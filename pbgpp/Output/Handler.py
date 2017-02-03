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

from pbgpp.BGP.Message import BGPMessage
from pbgpp.Output.Exceptions import OutputHandlerError
from pbgpp.Output.Formatter import BGPFormatter
from pbgpp.Output.Pipe import BGPPipe


class OutputHandler:

    def __init__(self, message, filter=[], formatter=None, pipe=None):
        # Pre-check variables
        if not isinstance(message, BGPMessage):
            raise OutputHandlerError("packet must be instance of BGPPacket.")

        if not isinstance(formatter, BGPFormatter):
            raise OutputHandlerError("formatter must be instance of Formatters.")

        if not isinstance(pipe, BGPPipe):
            raise OutputHandlerError("pipe must be instance of Pipe.")

        # Assign class variables
        self.message = message

        self.filter = filter
        self.formatter = formatter
        self.pipe = pipe

        self.output = None

    def __filter(self):
        # Apply runtime filter - maybe the message isn't even required to be displayed.
        # In this case we don't need to waste computing time on formatting and piping.
        # Filters are always connected with a logical AND. One filter is able to allow multiple values
        # for one specific filter. Those values are linked with a logical OR.
        # Example: --filter-next-hop 11.11.11.11 --filter-next-hop 12.12.12.12 --filter-source-ip 13.13.13.13
        # Example: Those filters will filter packets that have
        # Example: ((next-hop == 11.11.11.11)
        # Example: _OR_ (next-hop == 12.12.12.12))
        # Example: _AND_ (source-ip == 13.13.13.13)

        for f in self.filter:
            if self.message is None:
                # We don't need to try to apply filters on a message that was already set to None
                break

            # Apply post-parsing filter to parsed packet
            self.message = f.apply(self.message)

    def __format(self):
        # Format the packet or a single message (e.g. apply JSON-formatting)
        try:
            self.output = self.formatter.apply(self.message)
        except TypeError:
            self.output = None
        except AttributeError:
            self.output = None

    def __pipe(self):
        # Pipe the filtered and formatted output (e.g. into a file or into stdout)
        self.pipe.output(self.output)

    def handle(self):
        # Filters will set self.packet to None if no filter will apply
        if self.message is not None:
            self.__filter()

            if self.message is not None:
                self.__format()

                if self.output is not None:
                    self.__pipe()
                else:
                    # Don't display message if there occurred an error during formatting
                    pass

            else:
                # Don't display message if there occurred an error during filtering
                # or if the packet is set to None during filtering
                pass
