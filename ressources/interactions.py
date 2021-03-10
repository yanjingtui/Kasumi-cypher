#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from math import inf
import os
import time

from ressources import prng
from datetime import datetime

import ressources.config as config
import ressources.bytesMethods as bm

import base64



#
# Console Interactions
#

def enumerate_menu(choices):
    """
    Menu enumeration
    """
    for i, elt in enumerate(choices):
        print(f"\t({i + 1}) - {elt}")


def query_yn(question, default="yes"):
    """Ask a yes/no question via input() and return their answer."""

    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}

    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        choice = input(question + prompt).lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")


def readFromUser(msg="Enter the message :"):
    from sys import stdin

    phrase = ""

    print(msg + "\n")

    for line in stdin:
        if line == '\n':  # If empty string is read then stop the loop
            break
        else:
            phrase += line

    # [:-1] to delete the last '\n'
    return phrase[:-1]


#
# LOOP FUNCTION TO GET INPUT
#

def getFile():
    print("Please enter the filename with its extension (source folder is processing):")

    while True:
        f = input("> ")
        if f == "c":
            return None
        elif isFileHere(f, config.DIRECTORY_PROCESSING):
            return config.DIRECTORY_PROCESSING + f
        else:
            print(f"Error: file '{f}' not found, enter [c] to go back or enter a valid filename:")


def getInt(default=256, expected="hash", size=False, limit: int = inf):
    print(f"Enter {expected} ({default} by default):")

    while True:
        i = input("> ")
        if i == "":
            return default
        else:
            try:
                val = int(i)
                if val >= 0 and (not size or (val % 8 == 0 and val >= 32)) and val <= limit:
                    return val
                else:
                    print(f"Error: {i} is not a valid {expected}, leave blank or enter a valid {expected}:")

            except ValueError:
                print(f"'{i}' is not an integer, leave blank or enter a valid {expected}:")


def getFloat(default=0.5, expected="value", limit: int = inf):
    print(f"Enter {expected} ({default} by default):")

    while True:
        f = input("> ")
        if f == "":
            return default
        else:
            try:
                val = float(f)
                if val >= 0 and val <= limit:
                    return val
                else:
                    print(f"Error: {f} is not a valid {expected}, leave blank or enter a valid {expected}:")

            except ValueError:
                print(f"'{f}' is not an float, leave blank or enter a valid {expected}:")


def getRange(default=(1, 1)):
    while True:
        t1 = getInt(default[0], "min")
        t2 = getInt(default[1], "max")

        if t1 <= t2:
            return (t1, t2)

        else:
            print(f'Error: ({t1}, {t2}) is not a valid range, leave blank or enter a valid range')


def getb64(expected="message", size=-1):
    import base64
    import binascii

    print(f"Enter {expected} in base64:")
    while True:
        i = input("> ")
        if i == "c":
            return None
        else:
            try:
                data = base64.b64decode(i)
                if size == -1 or len(data) == size:
                    return data
                else:
                    print(f'Error: {expected} must be {size} bytes long, enter [c] to go back or enter a valid base64')
            except binascii.Error:
                print(
                    f'Error: Unable to decode "{i}", the format is not in base64, enter [c] to go back or enter a valid base64')


def cipher_method_choice():
    print("Choice cypher method : ")
    print(" 1 - ECB \n 2 - CBC \n 3 - PCBC (Recommended) \n 4 - CTR (Stream) \n 5 - GCM (Authentification)")

    cipher_method = getInt(3, "choices")

    # Cipher method verification
    if cipher_method > 5:
        print("Error: Please enter a cipher method in 1-5.")
        time.sleep(1)

        from main import menu
        menu()

    elif cipher_method == 1:
        answer = query_yn("ECB is not recommended for use in cryptographic protocols. Are you sure?")
        if answer:

            return cipher_method
        else:

            return cipher_method_choice()

    return cipher_method

#
# File Manager Method
#

def findFile(ext="", directory=config.DIRECTORY_PROCESSING):
    """
    To find a file given extension and return is name.
    """

    name = ""

    if ext == "":
        # Return the first file in the directory that is not crypted
        for f in os.listdir(directory):
            if not (f.endswith("kat")):
                name = f
    else:
        for f in os.listdir(directory):
            if f.endswith(ext):
                name = f

    return name


def isFileHere(name: str, directory=config.DIRECTORY_GEN):
    """Return if given name file's is here or is not."""
    return os.path.isfile(directory + name)


def handleDirectory(dirName: str, directory=config.DIRECTORY_GEN):
    """ If given directory doesn't exist, then create intA. """
    if not os.path.exists(directory + dirName):
        os.makedirs(directory + dirName)


def rmFile(name: str, directory=config.DIRECTORY_GEN):
    """Remove named file."""
    try:
        os.remove(directory + name)
    except FileNotFoundError:
        pass


def mvFile(name: str, src=config.DIRECTORY_PROCESSING, dst=config.DIRECTORY_GEN):
    """ Move named file """
    import shutil
    return shutil.move(src + name, dst)


def whatInThere(directory=config.DIRECTORY_FOUNT):
    """
    Return elements present in given directory in list format.
    """
    return [os.path.splitext(f)[0] for f in os.listdir(directory)]


def writeVartoFile(var: object, name: str, directory=config.DIRECTORY_GEN, ext: str = ".txt"):
    """Write given variable into a file with variable name"""
    # r+ for reading and writing
    name = directory + name
    with open(name + ext, "w+") as f:
        f.truncate(0)
        f.write(f"{var}")

    return True


def extractVarFromFile(fileName: str, directory=config.DIRECTORY_GEN, ext: str = ".kat"):
    """Extract variable contenant's from txt file."""
    import ast
    with open(directory + fileName + ext, "r+") as f:
        contents = f.read()
        try:
            extracted = ast.literal_eval(contents)
        except Exception:
            extracted = contents

    return extracted


#
# Key gestion
#

def getIntKey(data: bytes, keyNumber: int = 1):
    """
    Convert base64 key's into tuples of keyNumber integers.
    """
    assert isinstance(data, bytes) or isinstance(data, bytearray)

    if isinstance(keyNumber, str):
        keyNumber = int(keyNumber)

    if keyNumber != 1:
        keys = ()
        kL = []
        for i in range(keyNumber):
            kL.append(int.from_bytes(data[i * 2:i * 2 + 2], "big"))

        padding = keyNumber * 2
        for i, s in enumerate(kL):
            keys += (int.from_bytes(data[padding: padding + s], "big"),)
            padding = padding + s
    else:
        keys = bm.bytes_to_int(data)

    return keys


def getB64Keys(key):
    """
    Received in input key in tuple, bytes, list etc. and return key in base64.
    """
    import base64

    if isinstance(key, tuple):

        tw = bytearray()
        sizes = []

        for k in key:
            s = bm.bytes_needed(k)
            sizes.append(s)
            # Put the size into the coded b64
            tw += s.to_bytes(2, "big")

        for i, k in enumerate(key):
            tw += k.to_bytes(sizes[i], "big")

    elif isinstance(key, list):
        # E.g, ElGamal with M >= p (longer message)

        e = [getB64Keys(el) for el in key]

        tw = ''
        for el in e:
            tw += f"{el}|"

        tw = tw[:-1].encode()
    elif isinstance(key, bytes):
        # Already into bytes
        tw = key
    else:
        # uniq key
        tw = bm.multitype_to_bytes(key)

    return base64.b64encode(tw).decode()


def writeKeytoFile(key, fileName: str, directory=config.DIRECTORY_PROCESSING, ext: str = ".kpk") -> str:
    """
    Write key in b64 format to file .kpk with key length's as header.
    """

    if isinstance(key, tuple):
        size = str(len(key))

    elif isinstance(key, list):
        # size of each element
        size = len(key[0])
        size = f"L{size}"

    else:
        size = "1"

    b64K = getB64Keys(key)

    b64Key = size + b64K

    writeVartoFile(b64Key, fileName, directory, ext)

    return b64K


def extractKeyFromFile(fileName: str, directory=config.DIRECTORY_PROCESSING, ext: str = ".kpk"):
    """
    Extract key's from b64 format to tuples from katsumi public/private keys file's.
    """

    fileName += ext
    if isFileHere(fileName, directory):
        f = open(os.path.join(directory, fileName), "r+")
        b64data = f.read()
        f.close()

        from base64 import b64decode

        if b64data[0] == "L":
            # It's a list !
            # Case when message is longer than modulus -> separation into list of keys
            return [getIntKey(b64decode(el), b64data[1]) for el in b64decode(b64data[2:]).decode().split("|")]

        else:
            return getIntKey(b64decode(b64data[1:]), b64data[0])

    else:
        raise FileNotFoundError(f"File {fileName} not found")


def ask_key():
    import base64

    answer = query_yn("You have not yet defined a key, you want to enter one?", "no")

    key = bytearray()

    if answer:
        key = getb64("key", 16)

        if not key:
            katsumi_sym()

    else:
        import secrets as sr
        key = sr.randbits(128).to_bytes(16, "big")
        print("Your key was randomly generated: ", end="")
        print(base64.b64encode(key).decode())
        print("Key has been put in config")
        config.KEY = key

    return key


def getKeySize(key: object = "public_key") -> int:
    """
    Return size of current key based on prime fount's.
    """

    sizes = [int(elt.split("_")[0]) for elt in whatInThere()]

    if isinstance(key, str):
        pK = extractKeyFromFile(key, config.DIRECTORY_PROCESSING, ".kpk")
    else:
        pK = key

    bits = bm.bytes_needed(pK[0]) * 8

    import ressources.utils as ut

    return ut.closestValue(sizes, bits)

#
# Inversion Box
#
def handleInvBox(doIt: bool = False):
    """
    Deal with inversion box of given degree.

    doIt: argument for debugging, run directly the thing.
    """

    if doIt:
        import threading
        import time
        import cipher.symmetric.galois_Z2 as gz2

        th = threading.Thread(target=gz2.genInverses2)

        # This thread dies when main thread (only non-daemon thread) exits.
        th.daemon = True

        th.start()
        time.sleep(2)

    else:

        if not isFileHere("inversion_Sbox.txt"):

            print("A necessary file for the substitution has been deleted / corrupted from the system.\n")

            if query_yn(
                    "- Do you want to generate the inverse substitution box (No if you want to compute each time needed)? "):

                handleInvBox(True)

            else:
                config.GALOIS_WATCH = True

        else:

            config.INVERSIONS_BOX = extractVarFromFile("inversion_Sbox", ext=".txt")

            if len(config.INVERSIONS_BOX) != config.NBR_ELEMENTS:
                rmFile("inversion_Sbox.txt")

                handleInvBox()


def doSomethingElse(m=None):
    """
    Ask user if he want to do something and if yes, get back to main menu.
    """
    answer = query_yn("\nDo you want to do something else?")
    import main

    if m == None:
        m = main.menu

    print()

    if answer:

        return m()
    else:
        return main.selection_choice(-1)


#
# Prime number's fount gestion
#

def extract_safe_primes(nBits: int = 1024, allE: bool = True, easyGenerator: bool = False,
                        directory: str = config.DIRECTORY_FOUNT, Verbose=False):
    """
    Return list of tuples (Safe_Prime, Sophie_Germain_Prime) for given n bits.
    If list doesn't exist, create one with 1 tuple.

    all :
        - True for all list
        - False for one random tuple
    """
    name = f"{str(nBits)}_bits"

    if not isFileHere(name + ".txt", directory):
        print("File doesn't exist. Creating it with one element.")
        stockSafePrimes(nBits, 1)
        extract_safe_primes(nBits, allE, easyGenerator, directory)
    else:
        v = extractVarFromFile(name, directory, ".txt")

        if allE:
            return v
        else:
            import ressources.utils as ut

            s = ut.randomClosureChoice(v)

            if easyGenerator:
                from cipher.asymmetric.elGamal import isEasyGeneratorPossible

                if not isEasyGeneratorPossible(s):
                    while len(s) != 0 and not isEasyGeneratorPossible(s):
                        s = ut.randomClosureChoice(v)

                    if len(s) == 0 and not isEasyGeneratorPossible(s):
                        # It's the only ramaining element and intA's not possible to use easy gen with him.

                        if Verbose:
                            print(
                                "No safe prime available for easy generator creation into current {nBits} bits fountain's.")

                            question = query_yn(
                                "Do you want to generate one compatible with this condition (It can be long)? ")

                            if question:
                                s = prng.safePrime(nBits, easyGenerator=True)
                                if s:
                                    updatePrimesFount(s, nBits)
                                else:
                                    return s  # False
                            else:
                                return elGamalKeysGeneration()
                        else:
                            # No choice.
                            updatePrimesFount(s, nBits)
                else:
                    return s
            else:
                return s


def stockSafePrimes(n: int = 1024, x: int = 15, randomFunction=prng.xorshiftperso):
    """ 
    Stock x tuples of distincts (Safe prime, Sophie Germain prime) into a fount of given n bits length.
    """

    assert x > 0
    # Create an appropriated directory.
    handleDirectory("PrimeNumber's_Fount")

    # Safety check, if already exist, then you just update intA !
    if isFileHere(f"{str(n)}_bits.txt", config.DIRECTORY_FOUNT):
        print("\nData concerning this number of bits already exists. Update in progress.")
        Update = True
    else:
        print("\nData not existing, creating file...")
        Update = False

    if Update:
        fount = extract_safe_primes(n, Verbose=True)

    else:
        fount = []

    print(f"Computing in progress. Please wait ...")

    fount = prng.genSafePrimes(x, fount, n, randomFunction)

    if fount:
        print("Generation completed.\n")
        writeVartoFile(fount, f"{str(n)}_bits", config.DIRECTORY_FOUNT)
    else:

        print("Generation stopped.\n")


def updatePrimesFount(p: tuple, nBits: int):
    """
    Update prime number's fount (or create one with one element if not exist) and add given tuple if not present in stocked ones.
    """
    name = f"{str(nBits)}_bits"

    if not isFileHere(name + ".txt", config.DIRECTORY_FOUNT):
        print("\nData not existing, creating file...")
        stockSafePrimes(nBits, 0)
        updatePrimesFount(p, nBits)

    else:

        buffer = extractVarFromFile(name, config.DIRECTORY_FOUNT, ".txt")

        if p not in buffer:
            buffer.append(p)
            writeVartoFile(buffer, name, config.DIRECTORY_FOUNT)
            print(f"{p} successfully added to prime number's fount.\n")
        else:
            print(f"{p} already into prime number's fount. Not added.\n")


def primeNumbersFountain():
    """
    Deal with prime number's fountain.
    """



    print("The Foutain contains:\n")

    for elt in whatInThere():
        numberOfTuples = len(extract_safe_primes(elt.split('_')[0]))
        print(f"\t > {elt} - {numberOfTuples} tuples")

    choices = ["Generate and stock safe primes", "Update a list", "Delete a list", "Back to menu"]

    print("\n")
    enumerate_menu(choices)

    selection = getInt(2, "choices")

    def doSomethingFount(i: int):
        """ Handle choices for fountain. """


        if i == 1:
            print("How many bits wanted for this generation?")
            wanted = getInt(2048, "bits size", True)

            print("\nHow many generations?")
            numbers = getInt(1, "generations")

            stockSafePrimes(wanted, numbers)

            doSomethingElse(primeNumbersFountain)

        elif i == 2:
            print("Enter number of bits for updating corresponding one's :")
            wanted = getInt(2048, "bits size", True)

            print("\nHow many generations?")
            numbers = getInt(1, "generations")

            stockSafePrimes(wanted, numbers)

            doSomethingElse(primeNumbersFountain)

        elif i == 3:


            print("Enter the number of bits corresponding to the list you would like to be removed.")
            lnumber = getInt(2048, "bits size", True)
            name = f"{str(lnumber)}_bits.txt"

            if query_yn("Are you sure?"):
                rmFile(name, config.DIRECTORY_FOUNT)
                print(f"{name} removed successfully.\n")

                doSomethingElse(primeNumbersFountain)
            else:
                primeNumbersFountain()

        elif i == 4:
            import main
            main.menu()
        else:

            primeNumbersFountain()

    doSomethingFount(selection)


#
# El Gamal Gestion
#

def elGamalKeysGeneration():
    """
    Dealing with conditions for elGamal key generation.
    """
    from cipher.asymmetric import elGamal

    # Because here default is no so not(yes)
    if not query_yn("Do you want to use the fastest ElGamal key generation's (default: no)?", "no"):

        if query_yn("Do you want to choose the length of the key (default = 2048 bits)?", "no"):
            n = getInt(2048, "key size", True)
        else:
            n = 2048

        easy_gen = query_yn("Do you want to use easy Generator (fastest generation) (default: No)?", "no")

        if query_yn("Do you want to use the Prime Number's Fountain to generate the keys (fastest) (default: yes)?"):
            primes = extract_safe_primes(n, False, easy_gen, Verbose=True)
        else:
            primes = False

        print("\t.... Key generation in progress ....\n")

        elGamal.key_gen(n, primes, easy_gen, prng.xorshiftperso, True, True)
    else:
        n = 1024
        primes = extract_safe_primes(n, False, Verbose=True)

        print("\t.... Key generation in progress ....")

        elGamal.key_gen(n, primes, saving=True, Verbose=True)

    doSomethingElse(katsuAsymm)


def keys_verif(verif: bool = True):
    """
    Used to verify existence of private or/and public keys of ElGamal.
    """

    print("\nChecking the presence of keys in the system....")

    if isFileHere("public_key.kpk", config.DIRECTORY_PROCESSING):

        # from cipher.asymmetric import elGamal as elG

        print(f"\nPublic key is already here.\n")

        if isFileHere("private_key.kpk", config.DIRECTORY_PROCESSING):

            print(f"Private key is here too.\n")

            if verif and not query_yn("Do you want to keep them? (default: No)", "no"):
                rmFile("public_key.kpk", config.DIRECTORY_PROCESSING)
                rmFile("private_key.kpk", config.DIRECTORY_PROCESSING)
                rmFile("encrypted.kat", config.DIRECTORY_PROCESSING)
                return True

        else:
            print("Private key's missing.\n")

            if query_yn("Do you want to add them now?\n"):

                while not isFileHere("private_key.kpk", config.DIRECTORY_PROCESSING):
                    input("Please put your 'private_key.kpk' file into the 'processing' folder.")

                print("Find it !")

                keys_verif()
            else:
                katsuAsymm()

    elif isFileHere("private_key.kpk", config.DIRECTORY_PROCESSING):
        print("\nPrivate key's already here but not public one's.\n")

        if query_yn("Do you want to add them now? ( default: No)\n", "no"):

            while not isFileHere("public_key.kpk", config.DIRECTORY_PROCESSING):
                input("Please put your 'public_key.kpk' file into the 'processing' folder.")

            print("find it !")

            keys_verif()
        else:
            return True

    else:
        return True

    return False


#
# Diffie Hellman
#
def diffie_hellman_menu():
    """
    Sharing private key with Diffie Hellman.
    """
    import cipher.asymmetric.diffieHellman as dH

    choices = ["Choose agreement", "Process with agreement", "Back"]

    enumerate_menu(choices)

    selection = getInt(2, "choices")

    def doSomethingDH(i: int, processWithAgreement: bool = False):

        if i == 1:

            print("On what size n (bits) did you agree ?")

            size = getInt(2048, "bits size", True)

            print(f"Checking existence of fountain of {size} bits...")

            if not isFileHere(f"{size}_bits.txt", config.DIRECTORY_FOUNT):
                print("\n\tFile unavailable !")
                print("\n\fOne will be created.\n")
                fountain = False
            else:
                print("\n\tFile available !\n")
                fountain = True

            accord = dH.agreement(size, fountain)

            accord = writeKeytoFile(accord, "dH_agreement")
            print("According to the size of the private key, your agreement is : ", end="")
            print(accord)

            if query_yn("Do you want to process with given agreement now?"):
                doSomethingDH(2, True)
            else:
                doSomethingElse(diffie_hellman_menu)

        elif i == 2:

            if not processWithAgreement:
                if query_yn("Do you want to use the dH_agreement.kat file's? (default: Yes)"):
                    accord = extractKeyFromFile("dH_agreement")
                else:
                    accord = getIntKey(getb64("agreement"), 2)

            else:
                accord = extractKeyFromFile("dH_agreement")

            #

            print(f"\nNow, choose a secret value into [0, {accord[0]}]")

            import random as rd

            secret = getInt(rd.randrange(2, accord[0]), "your secret integer", False, accord[0])

            secret = dH.chooseAndSend(accord, secret, saving=True, Verbose=True)

            sended = getIntKey(getb64("his secret"), 1)

            dH_shared = dH.compute(accord, [secret, sended], saving=True)

            print("Shared key created.\n")
            print(f"\t > {dH_shared}\n")

            doSomethingElse(diffie_hellman_menu)

        elif i == 3:
            katsuAsymm()
        else:
            diffie_hellman_menu()

    doSomethingDH(selection)


#
# Display symmetric Menu
#

def katsumi_sym():
    import cipher.symmetric.ciphers as ciphers
    import main

    symmetric_choices = ["Encrypt a message.", "Decrypt a message.", "Back"]

    enumerate_menu(symmetric_choices)

    selection = getInt(1, "choices")

    def doSomethingSymm(i: int):
        """ Handle choices for symmetric things. """

        if i in [1, 2]:

            if not config.KEY:

                key = bytearray()

                import secrets as sr
                key = sr.randbits(128).to_bytes(16, "big")
                print("Your key was randomly generated: ", end="")
                print(base64.b64encode(key).decode())
                print("Key has been put in config")
                config.KEY = key

                return key
            else:
                key = config.KEY

        if i == 1:
            # Encryption
            cipher = cipher_method_choice()

            aad = ""
            file_to_encrypt = ""

            if cipher == 5:
                if query_yn(
                        "GCM allows to store authentified additional data (not encrypted), do you want to store some AAD?"):
                    aad = readFromUser()

            print("tobeenc.txt in processing will be encrypted")
            time.sleep(1)

            file_to_encrypt = "tobeenc.txt"
            data = bm.fileToBytes(file_to_encrypt)

            print("Encryption started....")

            begin_time = datetime.now()
            print(ciphers.run(data, file_to_encrypt, True, cipher, aad, key))
            end = datetime.now() - begin_time
            input(f"\nEncryption finished in {end} seconds !")
            doSomethingElse(katsumi_sym)

        elif i == 2:

            # Decryption    
            cipher = cipher_method_choice()
            file_to_encrypt = False

            print("tobeenc.txt.kat in processing will be encrypted")
            time.sleep(1)

            file_to_encrypt = "tobeenc.txt.kat"
            data = bm.fileToBytes(file_to_encrypt)

            print("Decryption started....\n")

            begin_time = datetime.now()

            print(ciphers.run(data, file_to_encrypt, False, cipher, "", key))

            end = datetime.now() - begin_time
            input(f"\nDecryption finished in {end} seconds !")

            doSomethingElse(katsumi_sym)

        elif i == 3:

            main.menu()
        else:

            katsumi_sym()

    doSomethingSymm(selection)


#
# Asymmetric Menu
#

def katsuAsymm():
    import main
    import cipher.asymmetric.elGamal as elG

    asymmetric_choices = ["Using ElGamal to generate public/private key pairs.", "Show keys",
                          "Encrypt a message with ElGamal", "Decrypt a message encrypted by ElGamal.",
                          "Share private key with Diffie-Hellman.",
                          "Keys deletion", "Back"]

    enumerate_menu(asymmetric_choices)

    selection = getInt(2, "choices")

    def doSomethingAssym(i: int):
        """ Handle choices for symmetric things. """

        if i == 1:
            print("You are going to generate public/private key pairs with ElGamal algorithm.")

            if keys_verif():
                elGamalKeysGeneration()
            else:

                print("Your current public key is: ", end="")
                print(getB64Keys(extractKeyFromFile("public_key")))

                doSomethingElse(katsuAsymm)

        elif i == 2:

            try:
                publicK = getB64Keys(extractKeyFromFile("public_key"))
                privateK = getB64Keys(extractKeyFromFile("private_key"))

                print("Public Key : ", end="")
                print(publicK)
                print()
                print("Private Key : ", end="")
                print(privateK)

            except FileNotFoundError:
                print("One key doesn't exist. Please regenerate them.")

            doSomethingElse(katsuAsymm)


        elif i == 3:

            if not isFileHere("public_key.kpk", config.DIRECTORY_PROCESSING):
                print("No public key found into the system...")
                time.sleep(1)
                doSomethingAssym(1)
            else:
                keys_verif(verif=False)
                answer = readFromUser().encode()
                e = elG.encrypt(answer, extractKeyFromFile("public_key", config.DIRECTORY_PROCESSING), saving=True)

                print(f" Saved encrypted message into appropriated file : ", end="")
                print(e)

                doSomethingElse(katsuAsymm)

        elif i == 4:

            print("Let's check if everything is there.")

            #####
            while not isFileHere("public_key.kpk", config.DIRECTORY_PROCESSING):
                input("Please put your 'private_key.kpk' file into the 'processing' folder.")

            print("Find it !\n")

            while not isFileHere("encrypted.kat", config.DIRECTORY_PROCESSING):
                input("Please put your 'encrypted.kat' file into the 'processing' folder.")

            print("Find it !\n")
            #####

            if query_yn("Do you want to use the encrypted.kat file's? (default: Yes)"):
                e = extractKeyFromFile("encrypted", config.DIRECTORY_PROCESSING, ".kat")
            else:
                e = getIntKey(getb64("key"), 2)

            d = elG.decrypt(e, extractKeyFromFile("private_key", config.DIRECTORY_PROCESSING), asTxt=True)

            print(d)

            doSomethingElse(katsuAsymm)

        elif i == 5:
            diffie_hellman_menu()

        elif i == 6:

            print("You're going to erase all key's from the system.\n")

            if query_yn("Are you sure?"):

                for f in ["public_key", "private_key", "dH_shared_key", "dH_agreement", "dH_sendable"]:
                    rmFile(f + ".kpk", config.DIRECTORY_PROCESSING)

                print("Done.\n")
                return doSomethingElse(katsuAsymm)

            else:
                katsuAsymm()

        elif i == 7:

            main.menu()
        else:
            katsuAsymm()

    doSomethingAssym(selection)


#
# Hash Menu
#

def katsu_hash_menu():
    import cipher.hashbased.hashFunctions as hf
    import base64

    choices = ["Generate a hash", "Check a hash", "Back to menu"]

    enumerate_menu(choices)

    selection = getInt(1, "choices")

    if selection == 1:

        size = getInt(256, "hash", True)

        if query_yn("Do you want to hash a file?", "no"):

            f = getFile()

            if f:
                print(f"File hash: {base64.b64encode(hf.sponge(bm.fileToBytes(f), size)).decode()}")

            else:
                katsu_hash_menu()
        else:
            msg = readFromUser("Enter the text to hash:")

            print(f"Text hash: {base64.b64encode(hf.sponge(msg.encode(), size)).decode()}")


    elif selection == 2:

        def verifyHash(h, msg):
            h2 = hf.sponge(msg, len(h) * 8)

            if h == h2:
                print("Hashes are the same !")
            else:
                print("Hashes are not the same !")

        h = getb64("hash")

        if h:
            if query_yn("Do you want to compare this hash to a file's one?", "no"):
                f = getFile()
                if f:
                    verifyHash(h, bm.fileToBytes(f))
                else:
                    katsu_hash_menu()
            else:
                verifyHash(h, readFromUser("Enter the text to compare with the hash:").encode())
        else:
            katsu_hash_menu()
    else:
        import main

        main.menu()

    doSomethingElse(katsu_hash_menu)


#
# Certificate Menu
#

def certificate():
    import cipher.asymmetric.certificate as ca

    choices = ["Get a public key certificate", "Show current digital certificate", "Back to menu"]

    enumerate_menu(choices)

    selection = getInt(1, "choices")

    if selection == 1:

        k = getb64("public key")

        if not k:
            certificate()

        ca.x509(k, out=False)
        print("Certifcate generated !")

        doSomethingElse(certificate)

    elif selection == 2:

        if not isFileHere("X509.ca", config.DIRECTORY_PROCESSING):
            print("Certificate not present into the system.")
            print("Getting back ..")
            time.sleep(1)
            certificate()
        else:
            f = open(config.DIRECTORY_PROCESSING + "X509.ca")
            for l in f.readlines():
                print(l)

        doSomethingElse(certificate)

    else:
        import main

        main.menu()

    doSomethingElse(certificate)
