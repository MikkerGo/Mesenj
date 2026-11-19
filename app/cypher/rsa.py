"""Реализация алгоритма RSA. Используется для шифрования ключа для симметричного шифрования AES"""

from cypher_share.hand_math import gcd, gen_prime
import secrets

def inverse(a: int, m: int) -> int:
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

def generate_keypair() -> tuple:
    """Генерирует пару из публичного и приватного ключей для алгоритма RSA"""
    while True:
        p = gen_prime()
        q = gen_prime()

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
            d = inverse(e, phi)
        except ValueError:
            continue
    
        return ((e, n), (d, n))

def encrypt_rsa(public_key: tuple, text: str) -> list:
    """Шифрует текст с помощью публичного RSA-ключа
    Args:
        public_key: Публичный ключ в формате кортежа (e, N)
        text: Текст, который необходимо зашифровать"""
    e, n = public_key
    encrypted_text = [pow(ord(char), e, n) for char in text]
    return encrypted_text

def decrypt_rsa(private_key: tuple, encrypted_text: str) -> str:
    """Расшифровывает текст при помощи приватного RSA-ключ
    Args:
        private_key: Приватный ключ в формате кортежа (d, N)
        encrypted_text: Зашифрованный при помощи публичного ключа текст"""
    d, n = private_key
    text = [chr(pow(char, d, n)) for char in encrypted_text]
    return ''.join(text)

if __name__=='__main__':
    text = "Ну я даже не знаю что сказать"
    public_key, private_key = generate_keypair()
    # print(private_key, public_key)
    encrypted_text = encrypt_rsa(public_key, text)
    print(encrypted_text)
    decrypted_text = decrypt_rsa(private_key, encrypted_text)
    print(decrypted_text)