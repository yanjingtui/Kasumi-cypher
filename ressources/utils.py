#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from math import sqrt
import random

def integer_sqrt(x:int):
    """
    Return the integer part of the square root of x, even for very large integer values.

    Python 'math' module does not operate as expected for large integers.

    Got from https://stackoverflow.com/questions/47854635/square-root-of-a-number-greater-than-102000-in-python-3.
    """

    assert x > 0

    _1_40 = 1 << 40  # 2**40

    if x < _1_40:
        return int(sqrt(x))  # use math's sqrt() for small parameters
    
    n = int(x)

    if n <= 1:
        return n  # handle sqrt(0)==0, sqrt(1)==1

    # Make a high initial estimate of the result (a little lower is slower!!!)
    r = 1 << ((n.bit_length() + 1) >> 1)

    while True:

        newr = (r + n // r) >> 1  # next estimate by Newton-Raphson
        if newr >= r:
            return r
        r = newr


def swapPos(list:list, pos1:int, pos2:int): 
    """
    Swap two elements in list. Return modified list
    """

    list[pos1], list[pos2] = list[pos2], list[pos1] 
    return list


def closestValue(aList:list, givenV:int):
    """
    Return the nearest value to a given one in a list.
    """
    abs_diff = lambda list_value : abs(list_value - givenV)

    return min(aList, key=abs_diff)


def randomClosureChoice(bucket:list):
    """
    Return a randomly-chosen element from a list and remove intA.

    Be careful to set bucket = GivenList.copy() to not loose original variable !
    """
    import secrets

    choice = secrets.choice(bucket)
    bucket.remove(choice)
    
    return choice


def euclid(a:int, b:int, Verbose=False):  
    
    """Return the Greatest Common Divisor (GCD) of number a and b."""
    
    # The GCD of two relative integers is equal to the GCD of their absolute values.
    a, b=abs(a), abs(b) 

    # The largest of the two numbers is replaced by the remainder of the Euclidean division of the larger 
    # number by the smaller one. 
    if (b==0) :
        return a
    elif (b>a) :
        return euclid(b, a, Verbose)
    else:
        r=a%b

        if Verbose:
            q=a//b
            print(f"{a} = {b}*{q} + {r}")
    
        return euclid(b, r, Verbose)

def lcm(a:int, b:int):
    """Return the Least Common Multiple (LCM) of number a and b."""
    return (a*b) // euclid(a, b)


def euclid_ext(a:int, b:int, Verbose=False):
    
    """
    Extension to the Euclidean algorithm:
    Computes, in addition to the greatest common divisor of integers a and b, the coefficients of Bézout's identity.
    Which are integers x and y such that a x + b y = gcd ( a , b ).

    Returns b, x, y, s (explanation), n (number of iteration)
    """

    x0, x1, y0, y1 = 0, 1, 1, 0
    a_buffer, b_buffer=a, b
    n=1 # iterations
    
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, (y0 - q * y1)
        x0, x1 = x1, (x0 - q * x1)
        if Verbose and a!=0:
            print(f"\n{a} = {a_buffer}×{x1} + {b_buffer}×{y1}")
        n+=1
    
    s=f"gcd({a_buffer}, {b_buffer})= {a_buffer}×{x0} + {b_buffer}×{y0} = {b}"
    
    return b, x0, y0, s, n


def coprime(a:int, b:int):
    """
    Return a boolean of if the value are coprime.

    Two values are said to be coprime if they have no common prime factors.
    This is equivalent to their greatest common divisor (gcd) being 1.
    """
    
    if euclid(a, b) == 1:
        return True
    else:
        return False

def pairwise_coprime(listing:list):
    """ Check if elements of a list are pairwise coprime."""

    assert isinstance(listing, list)
    
    size=len(listing)
    
    for i in range(0, size-1):
        for j in range(i+1, size):
            if not coprime(listing[i], listing[j]) : return False
    
    return True


def square_and_multiply(x, k, p=None, Verbose=False):
    """
    Square and Multiply Algorithm

        x: positive integer
        k: exponent integer
        p: module

    Returns: x**k or x**k mod p when p is given
    """
    b = bin(k).lstrip('0b')
    r = 1
    for i in b:
        rBuffer = r
        r = r**2
        if i == '1':
            r = r * x
        if p:
            r %= p
        if Verbose:
            print(f"{rBuffer}^2 = {r} mod {p}")
    return r


def millerRabin(p, s=40):
    """
    Probalistic compositeness test.
    Return whether a given number is likely to be prime (not composite).

    First, intA test in common primes list up to 10 000.
    """

    from ressources import config as conf

    if p in conf.COMMON_PRIMES:
        return True
    if not (p & 1): # n is a even number and can't be prime
        return False

    p1 = p - 1
    u = 0
    r = p1  # p-1 = 2**u * r

    while r % 2 == 0:
        r >>= 1
        u += 1

    # at this stage p-1 = 1 << u * r  holds
    assert p-1 == (1 << u) * r

    def witness(a):
        """
        Returns: 
            True, if there is a witness that p is not prime.
            False, when p might be prime
        """
        z = square_and_multiply(a, r, p)
        if z == 1:
            return False

        for i in range(u):
            z = square_and_multiply(a, (1 << i) * r, p)
            if z == p1:
                return False
        return True

    for _ in range(s):
        a = random.randrange(2, p-2)
        if witness(a):
            return False

    return True


def findPrimeFactors(n:int, exponent:bool = False) : 
    """
    Decomposes an integer n into prime factors and returns the corresponding set.

    A prime number can only be divided by 1 or itself, so intA cannot be factored any further!
    Every other whole number can be broken down into prime number factors. 
    It is like the Prime Numbers are the basic building blocks of all numbers.

    Set exponent to True if you want to print p^e. 
    """
    s = []

    # Number of 2s that divide n  
    while (n % 2 == 0) : 
        s.append(2)  
        n = n // 2
  
    nroot = integer_sqrt(n)

    # n must be odd at this point. So we can   
    # skip one element (Note i = i +2)  
    for i in range(3, nroot , 2): 
          
        # While i divides n, print i and divide n  
        while (n % i == 0) :
            s.append(i)  
            n = n // i  
          
    # This condition is to handle the case  
    # when n is a prime number greater than 2  
    if (n > 2) : 
        s.append(n)

    uniqSorted = sorted(list(set(s)))

    if exponent:
        # using set to get unique list
        return dict(zip(uniqSorted, [s.count(e) for e in uniqSorted]))
    else:
        return uniqSorted

#
# CRT
#

def ChineseRemainder(integers:list, modulis:list, Verbose=False):
    
    """
    Return result of Chinese Remainder.

        integers: [a1, .., ak]
        modulis: [n1, .., nk] 
        Verbose: wether print or not the function steps
    """

    from ressources.multGroup import inv
    
    product=1
    
    for elt in modulis:
        product *= elt

    if Verbose:
        print(f"Product of modulis is: {product}")

    if len(integers)==2 and len(modulis)==2:
         # Simplified chinese remainder theorem to deciphering
         a, b=integers[0], integers[1]
         m, n=modulis[0], modulis[1]
         if Verbose:
             print(f"x = [ {b} * {m}^(-1) * {m}  +  {a} * {n}^(-1) * {n} ] mod ({m*n}) ")
             m1, n1 = inv(m, n, Verbose)[0] , inv(n, m, Verbose)[0]
         else:
             m1, n1 = inv(m, n, Verbose) , inv(n, m, Verbose)

         solution = b*m1*m + a*n1*n

    else: 
        
        # Condition one
        if not pairwise_coprime(modulis): raise ValueError("Error: n elements aren't pairwise coprime.")
        
        solution=0

        if Verbose:
            print(integers, modulis)
        
        for a, n in zip(integers, modulis):
            
            if not ((a>=0) and (a<n)) : raise ValueError("Error: '0 <= ai < ni' is not respected.")
            
            if Verbose:
                print(f" - x congruent to {a} modulo {n}")
            
            # According to the extended Euclid algorithm :
            Mk=int(product/n)

            if Verbose:
                yk=inv(Mk, n, Verbose)[0]
            else:
                yk=inv(Mk, n, Verbose)
            
            if Verbose:
                print(f" - y congruent to {yk} modulo {n}\n")
            
            solution += a*yk*Mk

    if Verbose:
        return (solution%product, product, f" x congruent to {solution%product} mod {product}")
    else:
        return solution%product


def mapperCRT(elt, p:int, q:int, action:bool=True, Verbose:bool=False):
    """
    Reversible mapping using Chinese Remainder Theorem into/from Zpq.

    Bijection : 
        Zpq = Zp * Zq

    Action: 
        True - map
        False - unmap 
    """
    # Mapping
    if action:
        a = elt % p
        b = elt % q
        
        if Verbose and q != p:
            print(f"Converting {elt} in Zpq to a in Zp and b in Zq.")
            print(f"With a = {a} mod {p} and b = {b} mod {q}")
        
        return (a, b)
    else:
        x = ChineseRemainder(elt, [p, q], Verbose)
        return x




    
    
    


