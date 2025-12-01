# Standard library for dealing with the operating system
import os
# Standard library for converting data
import base64
# Standard library for wait/sleep
import time
# Standard cryptography library used for RSA encryption services
from cryptography.hazmat.primitives.asymmetric import rsa
# Standard cryptography library used for padding
from cryptography.hazmat.primitives.asymmetric import padding 
# Standard cryptography library used for serialization and hashes
from cryptography.hazmat.primitives import serialization, hashes


# The function which will generate the keys
def generate_keys():

    global public_key, private_key

    # Detecting the choice of the user for key generation
    chosen_input = input("Would you like to generate the RSA keys?: ")

    # If the user has chosen a variation of "yes" they will be forwarded here
    if chosen_input == "yes" and "Yes":
        # Printing the RSA keys
        # Printing the successful generation segment
        print("\nYou have chosen yes:")
        print("Generating RSA keys..")

        # Here we are generating both public and private key, serializing the public and private keys, and writing both the public and private keys as 'PEM' files
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # In this step we want to ensure that the public_key must be generated after the private_key in order, otherwise it will not generate
        public_key = private_key.public_key()
     
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode('utf-8')

        with open("public_key.pem", "w") as public_key_file:
             public_key_file.write(public_key_pem)

        with open("private_key.pem", "w") as private_key_file:
             private_key_file.write(private_key_pem)

        # Print the successful key generation and serialization
        print("Key generation was successful.")
        print("\n")
        print("------------------------------------------------")
        # Now sending the user back to the main menu with the public and private key
        main()
        return public_key, private_key 
    
    # If the user has chosen a variation of "no" they will be forwarded here
    elif chosen_input == "no" and "No":
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
    signature = input("Add your digital signature here: ")
    # Shifting the unique message into an encrypted version
    signature_in_bytes = signature.encode('utf-8')

    # Adding the encryption step onto the digital signature
    encrypted_signature = public_key.encrypt(signature_in_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    # Test case to showcase signature and encrypted signature
    print("\nPrinting your original signature..")
    # Printing the plaintext signature
    print(signature)
    print("\nPrinting the encrypted version of your signature below..")
    # Printing the encrypted signature
    print(encrypted_signature)
    print("\n")
    print("------------------------------------------------")
    # Now sending the user back to the main menu with the public and private key
    main()

# The function which will secure the digital signature
# The digital signature will be secured from the 
def secure_signature():
    print("Your signature successfully authenticated!")


# The function which will decrypt the digital signature
# The digital signature will be decrypted from the
def output_signature():
    print("Your signature will now be shown below: ")


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
        # This part of the menu correlates to adding and encrypting your own unique message to the key
        print("2. To add your digital signature")
        # This part of the menu correlates to securing said message
        print("3. To secure your digital signature")
        # This part of the menu correlates to outputing and decrypting your unique message 
        print("4. To output your digital signature")
        # This part of the menu is simply to exit the menu
        print("5. To exit the main menu")
        print("------------------------------------------------")

        chosen_input = input("\nChoose a command option from the above menu: ")

        # If the first is chosen then: generate the RSA key pair
        if chosen_input == "1" and "1.":
                print("\nForwarding to key generation...")
                generate_keys()
        # If the second is chosen then: add and encrypt the user's unique message/signature
        elif chosen_input == "2" and "2.":
                print("\nNow adding your digital signature...")
                add_signature()
        # If the third is chosen then: secure the user's unique message/signature
        elif chosen_input == "3" and "3.":
                print("\nNow securing your digital signature...")
                secure_signature()
        # If the fourth  is chosen then: output and decrypt the user's unique message/signature
        elif chosen_input == "4" and "4.":
                print("\nNow outputting your digital signature...")
                output_signature()
        # If the fifth is chosen then 
        elif chosen_input == "5" and "5.":
                print("\nForwarding to main menu exit...")
                exit_menu()
        else:
            # If none of the options, not even the exit worked, print this.
            print(f"\nAn error has occured: Incorrect choice selection.")


# Our basic function usage under one singular file
if __name__ == "__main__":
    main()