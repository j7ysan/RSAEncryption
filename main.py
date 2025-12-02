# Standard library for converting passwords
import getpass
# Standard library for converting data
import base64
# Standard library for wait/sleep
import time
# Standard cryptography library used for RSA encryption services and padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
# Standard cryptography library used for serialization and hashes
from cryptography.hazmat.primitives import serialization, hashes

# Making these for asking for secure outputs to validate user response
global enter_username
global enter_password 

# User verification/validation, extra step in security and output
enter_username = input("What would you like your username to be?: ")
enter_password = getpass.getpass("What would you like your password to be?: ")
print("\nAccount successfully created.")
print("------------------------------------------------")

# The function which will generate the keys
def generate_keys():

    global public_key, private_key

    # Detecting the choice of the user for key generation
    chosen_input = input("Would you like to generate the RSA keys?: ")

    # If the user has chosen a variation of "yes" they will be forwarded here
    if chosen_input == "yes" and "Yes":
        # Printing the RSA keys
        # Printing the successful generation segment
        print("\nGenerating RSA keys..")

        # Here we are generating both keys, serializing both keys, and writing both keys as PEM
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
     
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()).decode("utf-8")

        with open("TextEncryption/public_key.pem", "w") as public_key_file:
             public_key_file.write(public_key_pem)

        with open("TextEncryption/private_key.pem", "w") as private_key_file:
             private_key_file.write(private_key_pem)

        # Print the successful key generation and serialization
        print("Key generation was successful.")
        print("\n")
        print("------------------------------------------------")
        main()
        return public_key, private_key 
    
    # If the user has chosen a variation of "no" they will be forwarded here
    elif chosen_input == "no" and "No":
        # Returning the user back to the menu
        # Printing the unsucessful generation segment
        print("\nKey generation was unsuccessful..")
        print("Returning back to main menu.")
        print("\n")
        print("------------------------------------------------")
        main()
    else: 
        print(f"\nAn error has occurred: '{chosen_input}' Incorrect option, this choice requires a yes or no answer.")
        print("\nReturning back to main menu.")
        print("\n")
        print("------------------------------------------------")
        main()


# The function which will add the digital signature
# This digital signature will be added to the data.
def add_signature():

    global hidden_signature

    signature = getpass.getpass("Add your digital signature here: ")
    # Shifting the unique message into an encrypted version
    bytes_signature = signature.encode("utf-8")

    # Adding the encryption step onto the digital signature
    hidden_signature = public_key.encrypt(bytes_signature,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        
    # Print the successful signature addition
    print("Signature addition was successful.")
    print("\n")
    print("------------------------------------------------")
    main()
    return hidden_signature


# The function which will secure the digital signature
# The digital signature will be secured from the data and encoded through a layer of added security.
def secure_signature():

    global secured_signature

    # Using base64 to add security to the digital signature
    secured_signature = base64.urlsafe_b64encode(hidden_signature)

    # Now we save the secure signature for further output later
    with open("TextEncryption/encoded_signature.txt", "wb") as f:
         f.write(secured_signature)

    # Outputting to the user a successful secure of the digital signature
    print("\nYour signature successfully authenticated!")
    print("It is located in 'secure_signature.txt'.")
    print("\n")
    print("------------------------------------------------")
    main()
    return secured_signature


# The function which will decrypt the digital signature
# The digital signature will be decrypted from the original message, separate from the secured one.
def output_signature():
    # Obtaining our message from PEM
    with open("TextEncryption/private_key.pem", "r") as private_key_file:
        read_private_key = serialization.load_pem_private_key(private_key_file.read().encode("utf-8"),password=None)

    # Decrypting our signature/unique message
    shown_signature = read_private_key.decrypt(hidden_signature,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

    # Printing the unique message/result   
    chosen_input = input("Are you sure you will like to see the digital signature?: ")

    # Security check to output the signature, otherwise it will be unauthorized
    if chosen_input == "yes" and "Yes":
        chosen_user = input("\nEnter your username from before: ")
        chosen_pass = input("Enter your password from before: ")
        if chosen_user == enter_username:
            if chosen_pass == enter_password:
                print("Your signature will now be shown below: ")
                print("\n")
                print(shown_signature.decode("utf-8"))
                # Integrity check based off of the signature output, user should already be authorized at this point
                check_integrity = input("\nIs your signature still as you entered it?: ")
                if check_integrity == "yes" and "Yes":
                    print("\nSignature integrity has remained consistent.")
                    print("Authentication check passed.")
                    print("\n")
                    print("------------------------------------------------")
                    main()
                elif check_integrity == "no" and "No":
                    print("Signature integrity has been compromised.")
                    time.sleep(2)
                    print("\n")
                    print("Force exiting to refresh.....")
                    time.sleep(0.5)
                    print("Signature refreshing....")
                    time.sleep(0.5)
                    print("Signature refreshed...")
                    time.sleep(0.5)
                    print("Session terminated for refresh..")
                    time.sleep(0.5)
                    print("Please restart the system.")
                    exit()
            else:
                print("Invalid credentials.")
    elif chosen_input == "no" and "No":
            print("\n")
            print("Returning back to main menu.")
            print("\n")
            print("------------------------------------------------")
            main()
    else: 
        print(f"\nAn error has occurred: '{chosen_input}' Incorrect option, this choice requires a yes or no answer.")
        print("\nReturning back to main menu.")
        print("\n")
        print("------------------------------------------------")
        main()
             

# A simple exit from the main menu that we have created
def exit_menu():

    chosen_input = input("Are you sure you would like to close the main menu?: ")

    # If the user has chosen a variation of "yes" they will be forwarded here
    if chosen_input == "yes" and "Yes":
        time.sleep(2)
        print("\n")
        print("Main menu closed.")
        exit()
    # Else if the user has chosen a variation of "no" then they will be forwarded here
    elif chosen_input == "no" and "No":
        print("\n")
        print("Returning back to main menu.")
        print("\n")
        print("------------------------------------------------")
        main()
    else: 
        print(f"\nAn error has occurred: '{chosen_input}' Incorrect option, this choice requires a yes or no answer.")
        print("\nReturning back to main menu.")
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

        mainmenu_option = input("\nChoose a command option from the above menu: ")

        # If the first is chosen then: genereate keys
        if mainmenu_option == "1" and "1.":
                print("\nForwarding to key generation...")
                generate_keys()
        # If the second is chosen then: add and encrypt the user's unique message/signature
        elif mainmenu_option == "2" and "2.":
                print("\nNow adding your digital signature...")
                add_signature()
        # If the third is chosen then: secure the user's unique message/signature
        elif mainmenu_option == "3" and "3.":
                print("\nNow securing your digital signature...")
                secure_signature()
        # If the fourth  is chosen then: output and decrypt the user's unique message/signature
        elif mainmenu_option == "4" and "4.":
                print("\nNow attempting to output your digital signature...")
                output_signature()
        # If the fifth is chosen then 
        elif mainmenu_option == "5" and "5.":
                print("\nForwarding to main menu exit...")
                exit_menu()
        else:
            # If none of the options, not even the exit worked, print this.
            print(f"\nAn error has occurred: '{mainmenu_option}' Incorrect option, this choice requires a numbered response 1-5.")
            print("\nReturning back to main menu.")
            print("\n")
            print("------------------------------------------------")
            main()


# Our basic function usage under one singular file
main()