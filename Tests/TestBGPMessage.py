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

import unittest

from pbgpp.BGP.Statics import BGPStatics
from pbgpp.BGP.Message import BGPMessage


class TestBGPMessage(unittest.TestCase):

    # Method: BGPMessage.__init__
    # Tests if the initialization returns a valid BGPMessage object
    def test_init(self):
        a = BGPMessage("abc")
        self.assertIsInstance(a, BGPMessage)

    # Method: BGPMessage.__eq__
    # Tests if two identic BGPMessage objects are equal
    # Tests if two different BGPMessage objects are not
    # Tests if a BGPMessage object is not equal to a list object when using the "==" operator
    def test_eq(self):
        a = BGPMessage("abc")
        b = BGPMessage("abc")
        self.assertEqual(a, b)

        c = BGPMessage("def")
        self.assertNotEqual(a, c)

        self.assertEqual(a == list, False)

    # Method: BGPMessage.__len__
    # Tests if the len(object)-function returns a correct value
    def test_len(self):
        a = BGPMessage("abc")
        a.length = 10

        self.assertEqual(10, len(a))

    # Method: BGPMessage.get_length()
    # Tests if the get_length()-function returns a correct value
    def test_get_length(self):
        a = BGPMessage("abc")
        a.length = 10

        self.assertEqual(10, a.get_length())

    # Method: BGPMessage.get_type()
    # Tests if the get_type()-function returns a correct value
    def test_get_type(self):
        a = BGPMessage("abc")
        a.type = BGPStatics.MESSAGE_TYPE_OPEN

        self.assertEqual(BGPStatics.MESSAGE_TYPE_OPEN, a.get_type())

if __name__ == '__main__':
    unittest.main()
