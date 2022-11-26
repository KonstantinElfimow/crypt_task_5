#!/usr/bin/env python3

import collections
import random

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',  # кривая, которую я использую
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,  # простое число, задает размер конечного поля
    a=0,  # коэффициенты уравнения эллиптической кривой
    b=7,
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),  # базовая точка h*P (P-точка)
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,  # порядок подгруппы
    h=1,  # кофактор N/n
)


def inverse_mod(k, p):
    """Возвращает значение, обратное k по модулю p.
     Эта функция возвращает единственное целое число x, такое что (x * k) % p == 1.
     k должно быть ненулевым, а p должно быть простым числом.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')
    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    gcd, x, y = old_r, old_s, old_t
    assert gcd == 1
    assert (k * x) % p == 1
    return x % p


def is_on_curve(point):
    """Возвращает True, если заданная точка лежит на эллиптической кривой."""
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Возвращает -point."""
    assert is_on_curve(point)
    if point is None:
        # -0 = 0
        return None
    x, y = point
    result = (x, -y % curve.p)
    assert is_on_curve(result)
    return result


def point_add(point1, point2):
    """Возвращает результат point1 + point2 в соответствии с законом сложения точек."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)
    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1
    x1, y1 = point1
    x2, y2 = point2
    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None
    if x1 == x2:
        # Случай: point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # Случай: point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)
    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)
    assert is_on_curve(result)
    return result


def scalar_mult(k, point):
    """Возвращает k * точек, вычисленных с использованием алгоритма double и point_add."""
    assert is_on_curve(point)
    if k % curve.n == 0 or point is None:
        return None
    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))
    result = None
    addend = point
    while k:
        if k & 1:
            # Добавить.
            result = point_add(result, addend)
        # Double.
        addend = point_add(addend, addend)
        k >>= 1
    assert is_on_curve(result)
    return result


def make_keypair():
    """Генерирует случайную пару закрытый-открытый ключ."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


print('Curve:', curve.name)

# Алиса генерирует свою собственную пару ключей.
alice_private_key, alice_public_key = make_keypair()
print("Alice's private key:", hex(alice_private_key))
print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public_key))

# Боб генерирует свою собственную пару ключей.
bob_private_key, bob_public_key = make_keypair()
print("Bob's private key:", hex(bob_private_key))
print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public_key))

# Алиса и Боб обмениваются своими открытыми ключами и вычисляют общий секрет.
s1 = scalar_mult(alice_private_key, bob_public_key)
s2 = scalar_mult(bob_private_key, alice_public_key)
assert s1 == s2

print('Shared secret: (0x{:x}, 0x{:x})'.format(*s1))
print('Shared secret2: (0x{:x}, 0x{:x})'.format(*s2))
