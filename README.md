## GROUP 10 for COMP-490-AB1 - Network Security & Cryptography

---------------------------------------------------------
## Project Members:
Jasan Brar (1), Mihir Badhan (2), Yuvraj Singh (3).

---------------------------------------------------------
## Project Proposal:
Based off the use of RSA encryption hand-in-hand with digital signatures, such as text of someone's initials, even in the most bare bones degree.

---------------------------------------------------------
## Program Usage:
To use the program you must run the basic commands in respect to the project folder such as:

**python TextEncryption/main.py gen-keys**

**python TextEncryption/main.py encrypt**

**python TextEncryption/main.py decrypt**

**python TextEncryption/main.py verify**

**python TextEncryption/main.py output**

---------------------------------------------------------
## Command Explanation:
**python TextEncryption/main.py gen-keys:**
- Used to generate the keys for RSA encryption.
<br>
**python TextEncryption/main.py encrypt:**
- Used to encrypt the keys generated.
- Takes in userinput for the signature and text message associated, limited by code.
- Stashes text under 'data' - plain.
<br>
**python TextEncryption/main.py decrypt:**
- Used to decrypt the keys generated.
- Stashes decrypted text under 'data' - decrypted.
<br>
**python TextEncryption/main.py verify:**
- Used to verify the keys signature after encryption/decryption.
<br>
**python TextEncryption/main.py output:**
- Used to output the signature and text message associated.

---------------------------------------------------------
## Implementation
Using RSA encryption to encrypt keys and then recognizing a message from a user that should match an initial format, 'First Name', 'Last Name', restricted to 32 characters maximum each, and then encrypt such and then decrypt such to ensure that it was properly done.

