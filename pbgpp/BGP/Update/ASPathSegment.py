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

from pbgpp.BGP.Exceptions import BGPUpdateASPathSegmentFactoryError
from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Translation import BGPTranslation


class BGPUpdateASPathSegment:
    def __init__(self, segment_type, segments):
        self.segment_type = segment_type
        self.segments = segments

    @classmethod
    def factory(cls, segment_type, segments):
        if segment_type == BGPStatics.AS_PATH_SEGMENT_SET:
            return cls(segment_type, segments)

        if segment_type == BGPStatics.AS_PATH_SEGMENT_SEQUENCE:
            return cls(segment_type, segments)

        raise BGPUpdateASPathSegmentFactoryError("could not validate segment type.")

    def json(self):
        r = {
            "segment_type": self.segment_type,
            "segment_type_string": BGPTranslation.path_segment_type(self.segment_type),
            "segments": []
        }

        for s in self.segments:
            r["segments"].append(s)

        return r

    def __str__(self):
        # Display AS_SEQUENCE in brackets (it's an ordered list of ASN)
        # Display AS_SET as raw numbers
        return_string = ""

        if self.segment_type == BGPStatics.AS_PATH_SEGMENT_SEQUENCE:
            first_asn = True

            for asn in self.segments:
                if first_asn:
                    return_string += str(asn)
                    first_asn = False
                    continue

                return_string += " " + str(asn)

        elif self.segment_type == BGPStatics.AS_PATH_SEGMENT_SET:
            # Brackets because AS_SEQUENCE is an ordered list
            return_string += "("

            first_asn = True

            for asn in self.segments:
                if first_asn:
                    return_string += str(asn)
                    first_asn = False
                    continue

                return_string += " " + str(asn)

            # Close brackets
            return_string += ")"

        else:
            pass

        return None if len(return_string) == 0 else return_string
