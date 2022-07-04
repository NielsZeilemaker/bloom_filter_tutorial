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

        if __debug__:
            hypothetical_error_rates = [0.4, 0.3, 0.2, 0.1, 0.01, 0.001, 0.0001]
            logger.debug("m size:      %d    ~%d bytes", m_size, m_size / 8)
            logger.debug("k functions: %d", k_functions)
            logger.debug("hypothetical error rate: %s", " | ".join("%.4f" % hypothetical_error_rate for hypothetical_error_rate in hypothetical_error_rates))
            logger.debug("hypothetical capacity:   %s", " | ".join("%6d" % self.get_capacity(hypothetical_error_rate) for hypothetical_error_rate in hypothetical_error_rates))

        # determine hash function
        if m_size >= (1 << 31):
            fmt_code, chunk_size = "Q", 8
        elif m_size >= (1 << 15):
            fmt_code, chunk_size = "L", 4
        else:
            fmt_code, chunk_size = "H", 2

        # we need at most chunk_size * k bits from our hash function
        bits_required = chunk_size * k_functions * 8
        assert bits_required <= 512, "Combining multiple hashfunctions is not implemented, cannot create a hash for %d bits" % bits_required

        if bits_required > 384:
            hashfn = sha512
        elif bits_required > 256:
            hashfn = sha384
        elif bits_required > 160:
            hashfn = sha256
        elif bits_required > 128:
            hashfn = sha1
        else:
            hashfn = md5

        self._fmt_unpack = Struct(">" + (fmt_code * k_functions) + ("x" * (hashfn().digest_size - bits_required // 8))).unpack
        self._salt = hashfn()

    def __get_positions(self, key):
        h = self._salt.copy()
        h.update(key)
        yield from self._fmt_unpack(h.digest())

    def add(self, key):
        """
        Add KEY to the BloomFilter.
        """
        for pos in self.__get_positions(key):
            self._filter |= 1 << (pos % self._m_size)

    def __contains__(self, key):
        """
        Test if KEY is in the BloomFilter (might be a false positive)
        """
        for pos in self.__get_positions(key):
            if not self._filter & (1 << (pos % self._m_size)):
                return False
        return True

    def get_capacity(self, f_error_rate):
        """
        Returns the capacity given a certain error rate.
        @rtype: int
        """
        assert isinstance(f_error_rate, float)
        assert 0 < f_error_rate < 1
        return int(self._m_size * (log(2) ** 2 / abs(log(f_error_rate))))