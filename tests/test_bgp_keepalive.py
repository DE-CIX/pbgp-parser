import unittest
import pbgpp


class KeepaliveTestCase(unittest.TestCase):

    """
    VALID_KEEPALIVE_MESSAGE

    | ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff | 00 13           | 04                   |
    | 16 Bytes: Marker                                | 2 Bytes: Length | 1 Byte: Message Type |
    """
    VALID_KEEPALIVE_MESSAGE = "ffffffffffffffffffffffffffffffff001304"

    def test_keepalive_message(self):
        pass

    def test_plausibility_check(self):
        pass

    if __name__ == '__main__':
        unittest.main()
