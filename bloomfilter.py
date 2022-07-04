import logging
logger = logging.getLogger(__name__)

from hashlib import sha1, sha256, sha384, sha512, md5
from math import ceil, log
from struct import Struct
from binascii import hexlify, unhexlify

class BloomFilter:

    def __init__(self, m_size, k_functions):
        assert isinstance(m_size, int)
        assert 0 < m_size
        assert m_size % 8 == 0, "size must be a multiple of eight (%d)" % m_size
        assert isinstance(k_functions, int)
        assert 0 < k_functions <= m_size

        self._m_size = m_size
        self._k_functions = k_functions
        self._filter = 0

    def __get_positions(self, key):
        raise NotImplemented("return the positions for this key")

    def add(self, key):
        """
        Add KEY to the BloomFilter.
        """
        for pos in self.__get_positions(key):
            raise NotImplemented("turn on this bit in the bloomfilter")

    def __contains__(self, key):
        """
        Test if KEY is in the BloomFilter (might be a false positive)
        """
        for pos in self.__get_positions(key):
            raise NotImplemented("test if this bit is on in the bloomfilter")