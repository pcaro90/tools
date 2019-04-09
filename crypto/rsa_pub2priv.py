#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# Copyright (c) 2017 Pablo Caro. All Rights Reserved.
# Pablo Caro <me@pcaro.es> - https://pcaro.es/
# rsa_pub2priv.py
# ----------------------------------------------------------------------


import os
import subprocess
import sys
import tempfile


__version__ = '0.1'


def generate_der_file(p, q, e=0x10001):
    # Ref: https://stackoverflow.com/questions/19850283/how-to-generate-rsa-keys-using-specific-input-numbers-in-openssl
    # Ref: https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modinv(a, m):
        gcd, x, y = egcd(a, m)
        if gcd != 1:
            return None  # modular inverse does not exist
        else:
            return x % m

    n = p*q
    phi = (p-1)*(q-1)
    d = modinv(e, phi)

    e1 = d % (p-1)
    e2 = d % (q-1)

    coeff = modinv(q, p)

    template = (
        'asn1=SEQUENCE:rsa_key\n'
        '\n'
        '[rsa_key]\n'
        'version=INTEGER:0\n'
        'modulus=INTEGER:{0}\n'
        'pubExp=INTEGER:{1}\n'
        'privExp=INTEGER:{2}\n'
        'p=INTEGER:{3}\n'
        'q=INTEGER:{4}\n'
        'e1=INTEGER:{5}\n'
        'e2=INTEGER:{6}\n'
        'coeff=INTEGER:{7}\n'
    )

    der_content = template.format(n, e, d, p, q, e1, e2, coeff)

    der_file = tempfile.NamedTemporaryFile(mode='w+t')
    der_file.write(der_content)

    der_file.read()

    return der_file


def main():
    p = int(sys.argv[1])
    q = int(sys.argv[2])

    e = 0x010001

    # Get Exponent
    # openssl rsa -pubin -noout -text < public.pem
    #
    # Get Modulus
    # openssl rsa -pubin -noout -modulus < public.pem

    der_file = generate_der_file(p, q)

    der_binary = tempfile.NamedTemporaryFile()
    subprocess.run([
        'openssl',
        'asn1parse',
        '-genconf',
        der_file.name,
        '-out',
        der_binary.name,
    ])
    subprocess.run([
        'openssl',
        'rsa',
        '-in',
        der_binary.name,
        '-inform',
        'DER',
        '-out',
        'private.key'
    ])
    der_file.close()
    der_binary.close()


if __name__ == "__main__":
    main()
