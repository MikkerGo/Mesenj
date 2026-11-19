import struct

def rotate(v, c):
    return ((v << c) & 0xffffffff) | v >> (32 - c)

def quarter_round(x, a, b, c, d):
    """Функция "четверть-раунда", одна из ключевых функций ChaCha20: 
    сложение по модулю 2 ^^ 32, побитовое сложение по модулю 2 (xor), циклическое сдвиги влево.
    a, b, c, d - набор 32-разрядных чисел
    Args:
        x: Массив из 16 32-разрядных беззнаковых чисел
        a: первое число из набора
        b: второе число из набора
        c: третье число из набора
        d: четвёртое число из набора"""
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 7)

def yield_chacha20_xor_stream(key, iv, position=0):
    if not isinstance(position, int):
        raise TypeError('position must be int')
    if position & ~0xffffffff:
        raise ValueError('position is not uint32')
    if not isinstance(key, bytes):
        raise TypeError('key must be bytes')
    if not isinstance(iv, bytes):
        raise TypeError('iv must be bytes')
    if len(key) != 32:
        raise ValueError('key must be 32 bytes')
    if len(iv) != 12:
        raise ValueError('iv must be 12 bytes')

    ctx = [0] * 16
    ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)  # "expand 32-byte k"
    ctx[4:12] = struct.unpack('<8L', key)
    ctx[12] = position & 0xffffffff
    ctx[13:16] = struct.unpack('<3L', iv)
    print(' '.join(f'{w:08x}' for w in ctx))
    while True:
        x = list(ctx)
        for _ in range(10):
            quarter_round(x, 0, 4,  8, 12)
            quarter_round(x, 1, 5,  9, 13)
            quarter_round(x, 2, 6, 10, 14)
            quarter_round(x, 3, 7, 11, 15)
            quarter_round(x, 0, 5, 10, 15)
            quarter_round(x, 1, 6, 11, 12)
            quarter_round(x, 2, 7,  8, 13)
            quarter_round(x, 3, 4,  9, 14)
        for c in struct.pack('<16L', *((x[i] + ctx[i]) & 0xffffffff for i in range(16))):
            yield c
        ctx[12] = (ctx[12] + 1) & 0xffffffff


def chacha20_encrypt(data, key, iv=None, position=0):
    if not isinstance(data, bytes):
        raise TypeError('data must be bytes')
    if not isinstance(key, bytes):
        raise TypeError('key must be bytes')
    if len(key) != 32:
        raise ValueError('key must be exactly 32 bytes')
    if iv is None:
        iv = b'\0' * 12
    if not isinstance(iv, bytes):
        raise TypeError('iv must be bytes')
    if len(iv) != 12:
        raise ValueError('iv must be 12 bytes')

    return bytes(a ^ b for a, b in
                 zip(data, yield_chacha20_xor_stream(key, iv, position)))


def test_rfc8439_2_3_2_block():
    """§2.3.2 — блок keystream при counter=1.
    Ожидаемый state в RFC:
        61707865 3320646e 79622d32 6b206574
        03020100 07060504 0b0a0908 0f0e0d0c
        13121110 17161514 1b1a1918 1f1e1d1c
        00000001 09000000 4a000000 00000000
    """
    key   = bytes(range(32))                               # 00..1f
    nonce = bytes.fromhex("000000090000004a00000000")      # 12 байт
    expected_keystream = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c0680304 22aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    # stream — байты по одному; собираем первые 64
    gen = yield_chacha20_xor_stream(key, nonce, position=1)
    got = bytes(next(gen) for _ in range(64))
    assert got == expected_keystream

def test_rfc8439_2_4_2_encrypt():
    key   = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (b"Ladies and Gentlemen of the class of '99: "
                 b"If I could offer you only one tip for the future, "
                 b"sunscreen would be it.")
    # Байты 0..47 из RFC 8439 §2.4.2 — три полных блока
    expected_ct_prefix = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"     # ← исправлено
    )
    ct = chacha20_encrypt(plaintext, key, nonce, position=1)
    assert ct[:48] == expected_ct_prefix
    assert chacha20_encrypt(ct, key, nonce, position=1) == plaintext

def test_rfc8439_2_3_2_keystream():
    key   = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")  # ← 09, не 00
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    gen = yield_chacha20_xor_stream(key, nonce, position=1)
    got = bytes(next(gen) for _ in range(64))
    for i in range(64):
        if got[i] != expected[i]:
            print(f"FIRST DIFF at {i}: got {got[i]:02x} expected {expected[i]:02x}")
            break
    assert got == expected

if __name__ == '__main__':
   test_rfc8439_2_3_2_block()
   test_rfc8439_2_3_2_keystream()
   test_rfc8439_2_4_2_encrypt()