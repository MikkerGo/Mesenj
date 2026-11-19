import random


def gcd(a: int, b: int) -> int:
    """Рекурсивное нахождение наибольшего общего делителя"""
    return a if b == 0 else gcd(b, a % b)


def is_prime(n: int, k: int = 5) -> bool:
    """Вероятностный тест Миллера-Рабина для определения простоты числа
    Args:
        n: Проверяемое число
        k: Количество раундов проверки (вероятность ложноположительного ответа = 1/k)"""
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def gen_prime(bit_length: int = 128) -> int:
    """Генератор простого числа длиной bit_length
    Args:
        bit_length: Необходимое число разрядов в простом числе"""
    while True:
        a = random.getrandbits(bit_length)
        if is_prime(a):
            return a