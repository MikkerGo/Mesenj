import random
from typing import List



def gcd(a: int, b: int) -> int:
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


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


def pad_to_multiple(array: List[int], number_bytes: int) -> List[int]:
    # Рассчитываем, сколько байтов нужно добавить, чтобы длина стала кратной number_bytes
    padding_length: int = number_bytes - (len(array) % number_bytes)

    # Если длина уже кратна number_bytes, то добавлять ничего не нужно
    # Иначе дополняем массив `padding_length` нулевыми байтами
    return array if padding_length == number_bytes else array + [0] * padding_length


def left_shift(array: List[int], shift: int) -> List[int]:
    res: List[int] = array[:]
    for i in range(shift):
        temp: List[int] = res[1:]
        temp.append(res[0])
        res[:] = temp[:]

    return res


def right_shift(array: List[int], shift: int) -> List[int]:
    res: List[int] = array[:]
    for i in range(shift):
        tmp: List[int] = res[:-1]
        tmp.insert(0, res[-1])
        res[:] = tmp[:]

    return res


def galois_multiply(num: int, factor: int) -> int:
    """Функция умножения числа num на константу factor в поле Галуа (256).

    Принимает значение num (байт) и factor (коэффициент умножения, например, 0x02, 0x03 и т.д.).
    Использует многочлен AES (0x1B) для корректной модульной арифметики в поле Галуа.
    """
    result: int = 0
    for i in range(8):
        # Проверка, установлена ли текущая степень двойки в factor (например, 0x09 = 2^3 + 1)
        if factor & (1 << i):
            temp: int = num
            # Сдвигаем temp на i позиций влево с учетом умножения в поле Галуа.
            for _ in range(i):
                temp = (temp << 1) ^ 0x1b if temp & 0x80 else temp << 1
            result ^= temp  # Добавляем temp в result с помощью XOR.

    # Возвращаем только младшие 8 бит для ограничения до 1 байта.
    return result & 0xFF