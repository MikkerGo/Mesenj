"""Реализация алгоритма RSA. Используется для шифрования ключа симметричного шифрования AES"""

from cypher.cypher_share.hand_math import gcd, gen_prime
import secrets
from pathlib import Path
import base64

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def _int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b          # чтобы не читалось как отрицательное
    return b"\x02" + _len(len(b)) + b

def _seq(*items: bytes) -> bytes:
    body = b"".join(items)
    return b"\x30" + _len(len(body)) + body

def _read_tlv(data: bytes, pos: int):
    """Возвращает (tag, value, new_pos)."""
    tag = data[pos]; pos += 1
    ln  = data[pos]; pos += 1
    if ln & 0x80:
        nlen = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + nlen], "big")
        pos += nlen
    value = data[pos:pos + ln]
    if len(value) != ln:
        raise ValueError("truncated DER")
    return tag, value, pos + ln

def _read_int(data: bytes, pos: int):
    tag, value, pos = _read_tlv(data, pos)
    if tag != 0x02:
        raise ValueError(f"expected INTEGER, got 0x{tag:02x}")
    return int.from_bytes(value, "big"), pos

def _pem_to_der(pem: str) -> bytes:
    b64 = "".join(
        ln.strip() for ln in pem.strip().splitlines()
        if not ln.startswith("-----")
    )
    return base64.b64decode(b64)

class RSA:
    def __init__(self, keydir: str = '.keys'):
        self.public_key = None
        self.private_key = None
        try:
            base = Path(__file__).resolve().parent.parent
        except NameError:
            base = Path.cwd()
        self.keydir = (base / keydir).resolve()
        self.init_personal_keypare()

    @staticmethod
    def read_public_pem(pem: str):
        """Принимает PKCS#1 ('RSA PUBLIC KEY') и SPKI ('PUBLIC KEY'). Возвращает (n, e)."""
        der = _pem_to_der(pem)

        if "BEGIN RSA PUBLIC KEY" in pem:
            tag, body, _ = _read_tlv(der, 0)
            pos = 0
            n, pos = _read_int(body, pos)
            e, pos = _read_int(body, pos)
            return e, n

        if "BEGIN PUBLIC KEY" in pem:
            tag, outer, _ = _read_tlv(der, 0)              # SEQUENCE
            pos = 0
            _tag, _alg, pos = _read_tlv(outer, pos)        # AlgorithmIdentifier
            tag, bit, pos = _read_tlv(outer, pos)          # BIT STRING
            if tag != 0x03 or bit[0] != 0:
                raise ValueError("bad BIT STRING")
            tag, body, _ = _read_tlv(bit[1:], 0)           # SEQUENCE внутри BIT STRING
            pos = 0
            n, pos = _read_int(body, pos)
            e, pos = _read_int(body, pos)
            return n, e

        raise ValueError("unknown PEM header")

    @staticmethod
    def read_private_pem(pem: str) -> dict:
        """Принимает и PKCS#1 ('RSA PRIVATE KEY'), и PKCS#8 ('PRIVATE KEY')."""
        if "BEGIN RSA PRIVATE KEY" in pem:
            der = _pem_to_der(pem)
        elif "BEGIN PRIVATE KEY" in pem:
            der = _pem_to_der(pem)
            # PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE alg, OCTET STRING pkcs1 }
            tag, outer, _ = _read_tlv(der, 0)
            pos = 0
            _version, pos = _read_int(outer, pos)          # 0
            _tag, _alg, pos = _read_tlv(outer, pos)        # AlgorithmIdentifier
            tag, octet, pos = _read_tlv(outer, pos)        # OCTET STRING
            if tag != 0x04:
                raise ValueError("expected OCTET STRING")
            tag, inner, _ = _read_tlv(octet, 0)
            if tag != 0x30:
                raise ValueError("expected SEQUENCE inside OCTET STRING")
            der = inner
        else:
            raise ValueError("unknown PEM header")

        tag, body, _ = _read_tlv(der, 0)
        if tag != 0x30:
            raise ValueError("not a SEQUENCE")

        pos = 0
        out = {}
        for name in ("version", "n", "e", "d", "p", "q", "dp", "dq", "qinv"):
            out[name], pos = _read_int(body, pos)

        if pos != len(body):
            raise ValueError("trailing data after RSAPrivateKey")
        return out

    def public_pem(self, key) -> str:
        e, n = key
        der = _seq(_int(n), _int(e))                    # PKCS#1 RSAPublicKey
        b64 = base64.b64encode(der).decode("ascii")
        lines = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
        return f"-----BEGIN RSA PUBLIC KEY-----\n{lines}\n-----END RSA PUBLIC KEY-----\n"

    def private_pem(self, public_key, private_key, p: int, q: int) -> str:
        e, n = public_key
        d, _ = private_key
        if p < q:                      # qinv = q⁻¹ mod p, по соглашению p > q
            p, q = q, p
        dp   = d % (p - 1)
        dq   = d % (q - 1)
        qinv = self._inverse(q, p)

        der = _seq(
            _int(0),      # version
            _int(n),
            _int(e),
            _int(d),
            _int(p),
            _int(q),
            _int(dp),
            _int(dq),
            _int(qinv),
        )
        b64 = base64.b64encode(der).decode("ascii")
        lines = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
        return f"-----BEGIN RSA PRIVATE KEY-----\n{lines}\n-----END RSA PRIVATE KEY-----\n"

    def _inverse(self, a: int, m: int) -> int:
        if m <= 0:
            raise ValueError("m должно быть положительным")
        a %= m
        if a == 0:
            raise ValueError("обратного элемента не существует")

        m0 = m
        x0, x1 = 0, 1
        while a > 1:
            if m == 0:
                raise ValueError("обратного элемента не существует")
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0

        if a != 1:
            raise ValueError("обратного элемента не существует")

        return x1 % m0

    def generate_keypair(self, rsa_bits: int = 128) -> tuple:
        """Генерирует пару из публичного и приватного ключей для алгоритма RSA"""
        while True:
            p = gen_prime(rsa_bits)
            q = gen_prime(rsa_bits)

            if p == q:
                continue
            
            n = p * q
            phi = (p - 1) * (q - 1)

            # e = 65537
            while True:
                e = secrets.randbelow(phi - 4) + 3
                if gcd(e, phi) == 1:
                    break
                
            try:
                d = self._inverse(e, phi)
            except ValueError:
                continue
            
            return ((e, n), (d, n), p, q)

    def init_personal_keypare(self) -> None:
        self.keydir.mkdir(parents=True, exist_ok=True)
        public_keypath = self.keydir / "public_rsa.pem"
        private_keypath = self.keydir / "private_rsa.pem"

        if public_keypath.exists() and private_keypath.exists():
            try:
                with open(public_keypath, "r", encoding="utf-8") as f:
                    public_pem = f.read()
                self.public_key = self.read_public_pem(public_pem)

                with open(private_keypath, "r", encoding="utf-8") as f:
                    private_pem = f.read()
                pr = self.read_private_pem(private_pem)
                self.private_key = (pr["d"], pr["n"])

                # Санити-чек: p*q == n и e*d ≡ 1 mod φ.
                # Если файлы от разных пар — молча шифровать нельзя.
                if pr["p"] * pr["q"] != pr["n"]:
                    raise ValueError("p*q != n")
                if self.public_key[0] != pr["e"] or self.public_key[1] != pr["n"]:
                    raise ValueError("public/private keys mismatch")
                phi = (pr["p"] - 1) * (pr["q"] - 1)
                if (pr["e"] * pr["d"]) % phi != 1:
                    raise ValueError("e*d mod φ != 1")

                return
            except (OSError, ValueError, IndexError, KeyError) as exc:
                print(f"[RSA] не удалось прочитать ключи из {self.keydir}: {exc!r}; генерирую новые")
                # сбрасываем, чтобы не остаться с полу-ключами
                self.public_key = None
                self.private_key = None

        self.public_key, self.private_key, p, q = self.generate_keypair(1024)
        with open(public_keypath, "w", encoding="utf-8") as f:
            f.write(self.public_pem(self.public_key))
        with open(private_keypath, "w", encoding="utf-8") as f:
            f.write(self.private_pem(self.public_key, self.private_key, p, q))


    def encrypt_rsa(self, text: str, foreign_public_key = None) -> list:
        """Шифрует текст с помощью публичного RSA-ключа
        Args:
            public_key: Публичный ключ в формате кортежа (e, N)
            text: Текст, который необходимо зашифровать"""
        if foreign_public_key:
            e, n = foreign_public_key
        else:
            e, n = self.public_key
        encrypted_text = [pow(ord(char), e, n) for char in text]
        return encrypted_text
    
    def decrypt_rsa(self, encrypted_text: str) -> str:
        """Расшифровывает текст при помощи приватного RSA-ключ
        Args:
            private_key: Приватный ключ в формате кортежа (d, N)
            encrypted_text: Зашифрованный при помощи публичного ключа текст"""
        d, n = self.private_key
        text = [chr(pow(char, d, n)) for char in encrypted_text]
        return ''.join(text)

if __name__=='__main__':
    text = "Ну я даже не знаю что сказать"
    rsa_coder = RSA()
    # print(private_key, public_key)
    encrypted_text = rsa_coder.encrypt_rsa(text)
    # print(encrypted_text)
    decrypted_text = rsa_coder.decrypt_rsa(encrypted_text)
    print(decrypted_text)