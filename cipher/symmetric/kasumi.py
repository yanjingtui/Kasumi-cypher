#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import ressources.config as config
import ressources.bytesMethods as bm
import ressources.interactions as it
from cipher.symmetric.galois_Z2 import invertGalois2

import time


#
# Key Schedule
#

def set_key(km=config.KEY):
    '''Kasumi's keyscheduler.'''

    # Chosen as a "nothing up my sleeve" number
    nums = b'\x124Vx\x9a\xbc\xde\xff\xed\xcb\xa9\x87eC!\x00'

    # Additionally a modified key K', similarly divided into 16-bit sub keys K'i, is used.
    kp = bm.byte_operation(km, nums, "XOR")

    # The 128-bit key K is divided into eight 16-bit sub keys Ki
    skm, skp = bm.splitBytes(km, 2), bm.splitBytes(kp, 2)

    config.KL1 = [bytearray(bm.circularRotation(skm[x], 0, 1)) for x in range(0, 8)]
    config.KL2 = [skp[(x + 2) % 8] for x in range(0, 8)]
    config.KO1 = [bytearray(bm.circularRotation(skm[(x + 1) % 8], 0, 5)) for x in range(0, 8)]
    config.KO2 = [bytearray(bm.circularRotation(skm[(x + 5) % 8], 0, 8)) for x in range(0, 8)]
    config.KO3 = [bytearray(bm.circularRotation(skm[(x + 6) % 8], 0, 13)) for x in range(0, 8)]
    config.KI1 = [skp[(x + 4) % 8] for x in range(0, 8)]
    config.KI2 = [skp[(x + 3) % 8] for x in range(0, 8)]
    config.KI3 = [skp[(x + 7) % 8] for x in range(0, 8)]

    # SBoxes initialization considering the given master key !
    initRC4(km)

#
# Algorithm of kasumi
#
def kasumi(arr, encrypt=True):
    if (len(arr) > 8):
        return "Error: Kasumi takes 64 bits as 8 bytes array in input"
    else:
        config.WATCH_KASUMI_NUMBER += 1
        exTime = time.time()

        arr = bm.splitBytes(arr, 4)
        l = arr[0]
        r = arr[1]

        for i in range(0, 8):

            if not encrypt:
                i = 7 - i

            KO = [config.KO1[i], config.KO2[i], config.KO3[i]]
            KI = [config.KI1[i], config.KI2[i], config.KI3[i]]
            KL = [config.KL1[i], config.KL2[i]]
            lp = l

            if (i % 2 == 0):
                l = FL(KL, FO(KO, KI, l))
            else:
                l = FO(KO, KI, FL(KL, l))

            l = bm.byte_operation(l, r, "XOR")
            r = lp

        config.WATCH_GLOBAL_KASUMI += time.time() - exTime

        return r + l


#######
### FL
#######
def FL(pKL, arr):
    if (len(arr) != 4):
        raise ValueError("FL takes 32 bits as 4 bytes array in input")
    else:
        arr = bm.splitBytes(arr, 2)
        l = arr[0]
        r = arr[1]

        rp = bm.byte_operation(bm.circularRotation(bm.byte_operation(l, pKL[0], "AND"), 0, 1), r, "XOR")
        lp = bm.byte_operation(bm.circularRotation(bm.byte_operation(rp, pKL[1], "OR"), 0, 1), l, "XOR")

        # Inverted in Galois Field
        lp = invertGalois2(lp)
        rp = invertGalois2(rp)

        return lp + rp


#######
###FO
#######
def FO(pKO, pKI, arr):
    if (len(arr) != 4):
        raise ValueError("FO takes 32 bits as 4 bytes array in input")
    else:
        arr = bm.splitBytes(arr, 2)
        l = arr[0]
        r = arr[1]

        for i in range(0, 3):
            l = r
            r = bm.byte_operation(r, FI(bm.byte_operation(l, pKO[i], "XOR"), pKI[i]), "XOR")

        return l + r


#######
###FI
#######
def FI(b1, pKI):
    b1 = bm.circularRotation(b1, 1, 2)

    z = bm.splitBytes(pKI, 1)

    subZ1 = S1[int.from_bytes(z[0], "big")].to_bytes(1, "big")
    subZ2 = S2[int.from_bytes(z[1], "big")].to_bytes(1, "big")

    return bm.byte_operation(b1, subZ1 + subZ2, "XOR")


########################
### Substitution boxes
########################
# https://en.wikipedia.org/wiki/S-box
#######################################

S1 = []
S2 = []


# Using RC4 initialization and adding

def initRC4(masterKey):
    """Create a shaked array with two keys of length between 4 and 16 bytes."""

    global S1, S2

    l = len(masterKey)
    mid = int(l / 2)
    K1, K2 = masterKey[mid:], masterKey[:mid]

    if l < 8 or l > 24:
        return False

    S1, S2 = [i for i in range(0, 256)], [i for i in range(0, 256)]

    j = 0
    m = 0

    for i in range(0, 256):
        j = (j + S1[i] + K1[i % len(K1)]) % 256
        m = (m + S2[i] + K2[i % len(K2)]) % 256

        S1, S2 = bm.swapPos(S1, i, j), bm.swapPos(S2, i, m)

    return True
