from solution.bloomfilter import BloomFilter

def test_filter():
    b = BloomFilter(1024, 8)
    for i in range(1000):
        b.add(bytes(str(i), 'utf-8'))

    for i in range(1000):
        assert bytes(str(i), 'utf-8') in b