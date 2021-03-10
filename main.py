#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ressources import interactions as intA
from cipher.symmetric.galois_Z2 import GF2


import sys
import time


# Display main menu
def selection_choice(choice):
    if choice == 1:
        intA.katsumi_sym()

    elif choice == 2:
        intA.katsuAsymm()

    elif choice == 3:
        intA.katsu_hash_menu()

    elif choice == 4:
        intA.certificate()

    elif choice == 5:
        return intA.primeNumbersFountain()

    elif choice in [6, -1]:
        print("Good bye")
        sys.exit()

    else:
        print("invalid input, please enter something else")
        menu()


#
# menu choice
#

def menu():
    print(
        """
        ██████╗ ██╗   ██╗███╗   ██╗███████╗██╗  ██╗ ██████╗ ███╗   ██╗ ██████╗     ███╗   ███╗███████╗██╗
        ██╔══██╗██║   ██║████╗  ██║╚══███╔╝██║  ██║██╔═══██╗████╗  ██║██╔════╝     ████╗ ████║██╔════╝██║
        ██████╔╝██║   ██║██╔██╗ ██║  ███╔╝ ███████║██║   ██║██╔██╗ ██║██║  ███╗    ██╔████╔██║█████╗  ██║
        ██╔══██╗██║   ██║██║╚██╗██║ ███╔╝  ██╔══██║██║   ██║██║╚██╗██║██║   ██║    ██║╚██╔╝██║██╔══╝  ██║
        ██║  ██║╚██████╔╝██║ ╚████║███████╗██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝    ██║ ╚═╝ ██║███████╗██║
        ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝     ╚═╝     ╚═╝╚══════╝╚═╝
                                                                                                 
        Bonjour ô maître Rémi ! Que souhaitez vous faire aujourd’hui ?
        """
    )
    choices = ["Symmetric", "Asymmetric", "Hash", "Get X509 Certificate", "Prime Numbers Fountain's",
               "Exit"]

    intA.enumerate_menu(choices)

    try:
        selection = intA.getInt(1, "choices")
        selection_choice(selection)
    except KeyboardInterrupt:
        selection_choice(-1)


def main():
    # Galois field's initialization
    GF2(16)

    menu()


if __name__ == '__main__':
    main()
