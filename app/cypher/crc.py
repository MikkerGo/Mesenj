def create_table():
    a = []
    for i in range(256):
        k = i << 24;
        for _ in range(8):
            k = (k << 1) ^ 0x4c11db7 if k & 0x80000000 else k << 1
        a.append(k & 0xffffffff)
    return a

def crc32(bytestream):
    crc_table = create_table()
    crc = 0xffffffff
    for byte in bytestream:
        lookup_index = ((crc >> 24) ^ byte) & 0xff
        crc = ((crc & 0xffffff) << 8) ^ crc_table[lookup_index]
    return crc

if __name__ == '__main__':
    print(hex(crc32(b'123456789')))
