from os import getenv
import string
import random


def get_secret(secret, default=None):
    try:
        with open(f'/run/secrets/{secret}', 'r') as f:
            return f.read()
    except OSError:
        return default if default else getenv(secret)


def id_gen(size=12, chars=string.ascii_uppercase[:6] + string.digits):
    """
    Genera un cadena de texto y numeros aleatoria en hexadecimal

    :param size:
    :param chars:
    :return:
    """
    return ''.join(random.choice(chars) for _ in range(size))
