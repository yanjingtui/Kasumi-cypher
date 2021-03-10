

`Katsumi` is an interactive cryptographical tool.

**Designed** on Arch Linux and Windows 10 **for Linux and Windows operating systems**.

## Table of content

- [About](#About)
- [Installation](#Installation)
- [Overview](#Performance)
    - [Structure](#Structure)
    - [Implementation choices](#Implementation_choices)
        - [Prime Numbers Fountain's](#Prime_Numbers_Fountain's)
    - [Performances](#Performances)
    - [Improvements](#Improvements)
- [License](#License)
- [Documentation](#Documentation)
## About
It is a school cryptography projet for GS15.

## Installation
* Clone the repository then go to the eponymous folder and launch "main.py" with python 3.


## Overview
This project is about developing and modified a cipher [Kasumi's symmetric encryption](https://en.wikipedia.org/wiki/KASUMI) algorithm, then to the generation of a public/private key pair.
### Structure
The source code is ordered as follows:
* The ["core" folder](cipher/) contains all method of symmetric, asymmetric and hash-based encryption.
* The ["processing" folder](processing/) which contains all input and output of the program destined for the user (i.e. public/private keys, digital signatures and encrypted things).
* The ["resources" folder](ressources/) contains all the largest code files. This is where most of the primary functions reside.


### Implementation choices

* The primitive polynomial of the binary extension field GF(2) of degree 16 was found [online](https://www.partow.net/programming/polynomials/index.html) and hard-coded into a [config file](ressources/config.py)

* To make it easier to handle the inverses in the Galois fields, we have [pre-recorded in memory the inverses](ressources/generated/inversion_Sbox.txt) of the Galois field degree 16 (itself written in raw).

* The [Inversion_Sbox.txt](ressources/generated/inversion_Sbox.txt) is checked at each start and if it's corrupted (not here or wrong), the program will generate one before starting.

* Any generator for El-Gamal is designed to resist birthday attacks, and it's found via the principle of [Schnorr's group](https://en.wikipedia.org/wiki/Schnorr_group). More information by reading the code about El-Gamal [here](cipher/asymmetric/elGamal.py).

* The generation of safe prime numbers is done by optimizing the search. We start from p prime number and check if 2p+1 is also prime OR if (p-1)/2 is also prime. [The source code dedicated to this subject](ressources/prng.py) has been commented in order to understand the thinking process_of_c1_c2.

* For [RSA](cipher/asymmetric/RSA.py) or [ElGamal](cipher/asymmetric/elGamal.py) encryption/decryption, **if the message is longer than our current modulus, it causes problem to process_of_c1_c2** (i.e. Mathematically outside the modulus). To overcome this, we **use a reversible mapping function** : *If the input message is larger (after conversion in integer) than the module of our encryption algorithm, we divide said message into several parts strictly smaller than the size of the module (i.e. With a 128-bit key, a 488-bit message is divided into 120-bit sub-messages)*.

* Base64 is used instead of hexadecimal for storing and displaying encrypted keys and/or messages. **Base64 takes 4 characters for every 3 bytes, so it's more efficient than hex.**

#### Prime Numbers Fountain's

Generating safe primes can take a lot of computing time. 
To overcome this problem, we have imagined storing our safe primes in an accessible and editable location.
We decided to call this thing: [**The Prime Numbers Fountain's**](ressources/generated/PrimeNumber's_Fount)

With this method, the user can have safe prime numbers loaded in his free time and use them appropriately at the right time.

**Python natively uses only one core**. So [we have multiprocessed the safe prime number search](ressources/prng.py) using 85% of the core capacity.

### Performances
**Each measurement is based on a i5-1035G4 with 1.5GHz**.

* The generation of the inverses in a binary Galois field (Z2) of degree 16 takes about **117 secondes** (average over 5 trials).
* Generating a **safe prime of 512 bits** take at average **7.4 secondes** for 10 tests.
* Generating a **safe prime of 2048 bits** take at average **71 minutes** for 4 tests.

### Improvements
* Simulation of bloc-chain has bugs to run correctly.

## License
Katsumi is licensed under the terms of the MIT Licence 
and is available for free - see the [LICENSE.md](LICENSE.md) file for details.

