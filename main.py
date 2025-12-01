# Standard library for dealing with the operating system
import os
# Standard library for converting data
import base64
# Standard library for wait/sleep
import time
# Standard libraries used for RSA encryption services
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


# An output that will print our private key, PEM encoded
PRIVATE_KEY_FILE = "private_key.pem"
# An output that will print our public key, PEM encoded
PUBLIC_KEY_FILE = "public_key.pem"


# The function which will act to generate both the public and private key
def generate_keys():
    global public_key, private_key

    # Detecting the choice of the user for key generation
    chosen = input("Would you like to generate the RSA keys?: ")

    # If the user has chosen a variation of "yes" they will be forwarded here
    if chosen == "yes" and "Yes":
        # Printing the RSA keys
        # Printing the successful generation segment
        print("\nYou have chosen yes:")
        print("Generating RSA keys..")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        print("Key generation was successful.")
    # If the user has chosen a variation of "no" they will be forwarded here
    elif chosen == "no" and "No":
        # Returning the user back to the menu
        # Printing the unsucessful generation segment
        print("\nYou have chosen no:")
        print("Key generation was unsuccessful..")
        print("Returning back to main menu.")
        print("\n")
        print("------------------------------------------------")
        main()


# The function which will add the digital signature
# This digital signature will be added to the 
def add_signature():
    signature = input("Add your digital signature here:")
    print(signature)


# The function which will secure the digital signature
# The digital signature will be secured from the 
def secure_signature():
    print("Your signature successfully authenticated!")


# A simple exit from the main menu that we have created
def exit_menu():
    # Detecting the choice of the user for main menu exiting
    chosen = input("Are you sure you would like to close the main menu?: ")

    # If the user has chosen a variation of "yes" they will be forwarded here
    if chosen == "yes" and "Yes":
        time.sleep(2)
        print("\nYou have chosen yes:")
        print("Main menu closed.")
        exit()
    # Else if the user has chosen a variation of "no" then they will be forwarded here
    elif chosen == "no" and "No":
        print("\nYou have chosen no:")
        print("Returning back to main menu.")
        print("\n")
        print("------------------------------------------------")
        main()


# Our main function, this is our function that we're going to use that acts as a menu
# Considering our project revolves around RSA encryption in the form of a menu, we'll use each step that we proposed as a menu segment
# If the user decides each function should correlate to each part of the menu
def main():
        # Printing the main menu output
        print("<MAIN MENU>")
        print("------------------------------------------------")
        # This part of the menu correlates to the key creation 
        print("1. To generate the keys for RSA encryption")
        # This part of the menu correlates to adding your own unique message to the key
        print("2. To add your digital signature")
        # This part of the menu correlates to securing said message
        print("3. To secure your digital signature")
        # This part of the menu is simply to exit the menu
        print("4. To exit the main menu")
        print("------------------------------------------------")

        # Chosen is the choice that the user will make upon entering the main menu
        chosen = input("\nChoose a command option from the above menu: ")

        # If the first is chosen then: generate the RSA key pair
        if chosen == "1" and "1.":
                print("\nForwarding to key generation...")
                generate_keys()
        # If the second is chosen then: add the user's unique message/signature
        elif chosen == "2" and "2.":
                print("\nNow adding your digital signature...")
                add_signature()
        # If the third is chosen then: secure the user's unique message/signature
        elif chosen == "3" and "3.":
                print("\nNow securing your digital signature...")
                secure_signature()
        # If the fourth is chosen then 
        elif chosen == "4" and "4.":
                print("\nForwarding to main menu exit...")
                exit_menu()
        else:
            # If none of the options, not even the exit worked, print this.
            print(f"\nAn error has occured: Incorrect choice selection.")


# Our basic function usage under one singular file
if __name__ == "__main__":
    main()